#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <optional>
#include <stdexcept>
#include <memory>
#include <atomic>
#include <chrono>
#include <random>
#include <ctime>
#include <cwchar>

#include <windows.h>
#include <wininet.h>
#include <bcrypt.h>
#include <winsvc.h>
#include "windivert.h"

const std::wstring GITHUB_USER = L"Unkn0wnMe";
const std::wstring GITHUB_REPO = L"squadFix";
const std::wstring GITHUB_BRANCH = L"master";

const char* TARGET_HOST = "game-files.offworldindustries.com";
const char* TARGET_PATH = "/squad/serverlist.cfg";
const char* RESPONSE_FILENAME = "serverlist.cfg";
constexpr size_t MAX_TCP_PAYLOAD = 1400; // Safe MTU size

#define SERVICE_NAME L"SquadFixService"
#define SERVICE_DISPLAY_NAME L"SquadFix"
#define EVENT_SOURCE_NAME L"SquadFixService"

SERVICE_STATUS_HANDLE g_service_status_handle = NULL;
SERVICE_STATUS g_service_status = { 0 };
HANDLE g_service_stop_event = INVALID_HANDLE_VALUE;

class EventLogger;
class PacketInterceptor;

PacketInterceptor* g_active_interceptor = nullptr;

VOID WINAPI ServiceMain(DWORD, LPWSTR*);
VOID WINAPI ServiceCtrlHandler(DWORD);
void ReportSvcStatus(DWORD, DWORD, DWORD);

class InternetHandle {
    HINTERNET handle_ = NULL;
public:
    InternetHandle(HINTERNET h) : handle_(h) {}
    ~InternetHandle() { if (handle_) InternetCloseHandle(handle_); }
    operator HINTERNET() const { return handle_; }
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
};

template<typename T>
using BcryptHandle = std::unique_ptr<T, decltype(&BCryptDestroyHash)>;

class WinDivertHandle {
    HANDLE handle_ = INVALID_HANDLE_VALUE;
public:
    WinDivertHandle(const char* filter, WINDIVERT_LAYER layer, SHORT priority, UINT64 flags)
        : handle_(WinDivertOpen(filter, layer, priority, flags)) {}
    ~WinDivertHandle() { if (handle_ != INVALID_HANDLE_VALUE) WinDivertClose(handle_); }
    operator HANDLE() const { return handle_; }
    bool isValid() const { return handle_ != INVALID_HANDLE_VALUE; }
    WinDivertHandle(const WinDivertHandle&) = delete;
    WinDivertHandle& operator=(const WinDivertHandle&) = delete;
};

class EventLogger {
    HANDLE hEventSource_ = NULL;
    bool is_service_mode_;

public:
    EventLogger(bool service_mode) : is_service_mode_(service_mode) {
        if (is_service_mode_) {
            hEventSource_ = RegisterEventSourceW(NULL, EVENT_SOURCE_NAME);
        }
    }

    ~EventLogger() {
        if (hEventSource_) {
            DeregisterEventSource(hEventSource_);
        }
    }

    void log(WORD type, const std::wstring& message) {
        if (is_service_mode_) {
            if (hEventSource_) {
                const wchar_t* msg_ptr = message.c_str();
                ReportEventW(hEventSource_, type, 0, 0, NULL, 1, 0, &msg_ptr, NULL);
            }
        } else {
            WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
            if (type == EVENTLOG_ERROR_TYPE) color = FOREGROUND_RED | FOREGROUND_INTENSITY;
            else if (type == EVENTLOG_WARNING_TYPE) color = FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;
            else if (type == EVENTLOG_INFORMATION_TYPE) color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;

            CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
            GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &consoleInfo);
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
            
            (type == EVENTLOG_ERROR_TYPE ? std::wcerr : std::wcout) << message << std::endl;
            
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleInfo.wAttributes);
        }
    }
    
    void info(const std::wstring& message) { log(EVENTLOG_INFORMATION_TYPE, message); }
    void warn(const std::wstring& message) { log(EVENTLOG_WARNING_TYPE, message); }
    void error(const std::wstring& message) { log(EVENTLOG_ERROR_TYPE, message); }
};

std::optional<std::string> downloadFile(const std::wstring& url) {
    InternetHandle hInternet(InternetOpenW(L"SquadFix-Updater", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0));
    if (!hInternet) return std::nullopt;

    InternetHandle hUrl(InternetOpenUrlW(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0));
    if (!hUrl) return std::nullopt;

    std::string content;
    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        content.append(buffer, bytesRead);
    }
    return content;
}

std::optional<std::string> calculateHash(const std::string& filePath, LPCWSTR algorithm) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return std::nullopt;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, algorithm, NULL, 0))) return std::nullopt;
    auto closeAlgProvider = [](BCRYPT_ALG_HANDLE h) { BCryptCloseAlgorithmProvider(h, 0); };
    std::unique_ptr<void, decltype(closeAlgProvider)> algGuard(hAlg, closeAlgProvider);

    DWORD cbHashObject = 0, cbData = 0, cbHash = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    if (cbHashObject == 0 || cbHash == 0) return std::nullopt;

    std::vector<BYTE> pHashObject(cbHashObject);
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pHashObject.data(), cbHashObject, NULL, 0, 0))) return std::nullopt;
    BcryptHandle<void> hashGuard(hHash, BCryptDestroyHash);

    std::vector<char> buffer(4096);
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        if (file.gcount() > 0) {
            if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PBYTE)buffer.data(), (ULONG)file.gcount(), 0))) return std::nullopt;
        }
    }

    std::vector<BYTE> pHash(cbHash);
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, pHash.data(), cbHash, 0))) return std::nullopt;

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& b : pHash) ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

std::string getGmtTimeString(std::optional<FILETIME> ft_opt) {
    SYSTEMTIME st;
    if (ft_opt) {
        FileTimeToSystemTime(&*ft_opt, &st);
    } else {
        GetSystemTime(&st);
    }
    
    char buf[128];
    std::tm t = {};
    t.tm_year = st.wYear - 1900;
    t.tm_mon = st.wMonth - 1;
    t.tm_mday = st.wDay;
    t.tm_hour = st.wHour;
    t.tm_min = st.wMinute;
    t.tm_sec = st.wSecond;
    t.tm_wday = st.wDayOfWeek;

    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &t);
    return buf;
}

std::string generateRandomHexString(size_t len) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << distrib(gen);
    }
    return ss.str();
}

class PacketInterceptor {
    std::atomic<bool> stop_requested_ = false;
    EventLogger& logger_;

public:
    PacketInterceptor(EventLogger& logger) : logger_(logger) {}

    void stop() {
        stop_requested_ = true;
    }

    void run() {
        logger_.info(L"Starting Packet Interceptor...");
        
        performUpdate();

        std::string response_file_content;
        WIN32_FILE_ATTRIBUTE_DATA file_attr;
        if (!GetFileAttributesExA(RESPONSE_FILENAME, GetFileExInfoStandard, &file_attr)) {
             logger_.error(L"FATAL: Cannot get attributes of " L"serverlist.cfg" L". Exiting.");
             return;
        }

        {
            std::ifstream file_stream(RESPONSE_FILENAME, std::ios::binary);
            if (!file_stream) {
                logger_.error(L"FATAL: Cannot open " L"serverlist.cfg" L". Exiting.");
                return;
            }
            std::stringstream buffer;
            buffer << file_stream.rdbuf();
            response_file_content = buffer.str();
        }

        std::string full_http_response = generateHttpResponse(response_file_content, file_attr.ftLastWriteTime);

        const char* filter = "outbound and tcp.DstPort == 80";
        WinDivertHandle handle(filter, WINDIVERT_LAYER_NETWORK, 0, 0);

        if (!handle.isValid()) {
            logger_.error(L"Failed to open WinDivert. Make sure it is installed and the program is run with Administrator privileges. WinDivert error: " + std::to_wstring(GetLastError()));
            return;
        }

        logger_.info(L"WinDivert opened successfully. Listening for Squad HTTP requests...");
        logger_.info(L"Target: GET http://" L"game-files.offworldindustries.com" L"/squad/serverlist.cfg");

        char packet[WINDIVERT_MTU_MAX];
        UINT packet_len;
        WINDIVERT_ADDRESS addr;

        while (!stop_requested_) {
            if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr)) {
                if (stop_requested_) break;
                logger_.error(L"Failed to receive packet (error " + std::to_wstring(GetLastError()) + L"). Exiting.");
                break;
            }

            PWINDIVERT_IPHDR ip_header;
            PWINDIVERT_TCPHDR tcp_header;
            PVOID payload;
            UINT payload_len;

            WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, NULL, &tcp_header, NULL, &payload, &payload_len, NULL, NULL);

            if (tcp_header == NULL || payload == NULL || payload_len == 0) {
                WinDivertSend(handle, packet, packet_len, NULL, &addr);
                continue;
            }

            std::string request_str(static_cast<const char*>(payload), payload_len);
            bool is_target_request = (request_str.find(std::string("GET ") + TARGET_PATH) != std::string::npos) &&
                                     (request_str.find(std::string("Host: ") + TARGET_HOST) != std::string::npos);

            if (is_target_request) {
                logger_.info(L"Target request intercepted! Sending emulated response...");

                char response_packet_base[WINDIVERT_MTU_MAX];
                UINT base_headers_len = (UINT)((char*)payload - packet);
                
                memcpy(response_packet_base, packet, base_headers_len);

                auto resp_ip_header = (PWINDIVERT_IPHDR)response_packet_base;
                auto resp_tcp_header = (PWINDIVERT_TCPHDR)(response_packet_base + sizeof(WINDIVERT_IPHDR));

                std::swap(resp_ip_header->SrcAddr, resp_ip_header->DstAddr);
                std::swap(resp_tcp_header->SrcPort, resp_tcp_header->DstPort);

                UINT32 initial_ack_num = htonl(ntohl(tcp_header->SeqNum) + payload_len);
                UINT32 initial_seq_num = tcp_header->AckNum;

                size_t bytes_sent = 0;
                while (bytes_sent < full_http_response.length()) {
                    char current_chunk_packet[WINDIVERT_MTU_MAX];
                    memcpy(current_chunk_packet, response_packet_base, base_headers_len);

                    auto chunk_ip_header = (PWINDIVERT_IPHDR)current_chunk_packet;
                    auto chunk_tcp_header = (PWINDIVERT_TCPHDR)(current_chunk_packet + sizeof(WINDIVERT_IPHDR));

                    size_t remaining_bytes = full_http_response.length() - bytes_sent;
                    size_t chunk_size = min(remaining_bytes, MAX_TCP_PAYLOAD);

                    memcpy(current_chunk_packet + base_headers_len, full_http_response.c_str() + bytes_sent, chunk_size);
                    
                    UINT current_packet_len = base_headers_len + (UINT)chunk_size;

                    chunk_tcp_header->AckNum = initial_ack_num;
                    chunk_tcp_header->SeqNum = htonl(ntohl(initial_seq_num) + (UINT32)bytes_sent);
                    chunk_tcp_header->Rst = 0;
                    chunk_tcp_header->Syn = 0;
                    chunk_tcp_header->Ack = 1;
                    chunk_tcp_header->Psh = 1;
                    chunk_tcp_header->Fin = ((bytes_sent + chunk_size) >= full_http_response.length()) ? 1 : 0;
                    chunk_ip_header->Length = htons(current_packet_len);
                    
                    addr.Outbound = 0;
                    WinDivertHelperCalcChecksums(current_chunk_packet, current_packet_len, &addr, 0);

                    if (!WinDivertSend(handle, current_chunk_packet, current_packet_len, NULL, &addr)) {
                         logger_.error(L"Failed to send chunk. Error: " + std::to_wstring(GetLastError()));
                         break;
                    }

                    bytes_sent += chunk_size;
                }
                logger_.info(L"Response sent successfully.");
                continue;
            }
            WinDivertSend(handle, packet, packet_len, NULL, &addr);
        }
        logger_.info(L"Packet Interceptor stopped.");
    }

private:
    void performUpdate() {
        logger_.info(L"Checking for serverlist.cfg updates...");
        
        std::wstring sha_url = L"https://raw.githubusercontent.com/" + GITHUB_USER + L"/" + GITHUB_REPO + L"/" + GITHUB_BRANCH + L"/serverlist.cfg.sha";
        auto remote_sha_opt = downloadFile(sha_url);

        if (remote_sha_opt) {
            std::string remote_sha = *remote_sha_opt;
            remote_sha.erase(std::remove_if(remote_sha.begin(), remote_sha.end(), ::isspace), remote_sha.end());
            std::transform(remote_sha.begin(), remote_sha.end(), remote_sha.begin(), ::tolower);

            auto local_sha_opt = calculateHash(RESPONSE_FILENAME, BCRYPT_SHA256_ALGORITHM);
            std::string local_sha = local_sha_opt.value_or("");

            if (local_sha != remote_sha) {
                logger_.warn(local_sha.empty() ? L"Local file not found. Downloading..." : L"New version available. Downloading...");

                std::wstring file_url = L"https://raw.githubusercontent.com/" + GITHUB_USER + L"/" + GITHUB_REPO + L"/" + GITHUB_BRANCH + L"/serverlist.cfg";
                auto new_content_opt = downloadFile(file_url);

                if (new_content_opt) {
                    std::ofstream out_file(RESPONSE_FILENAME, std::ios::binary);
                    out_file << *new_content_opt;
                    out_file.close();
                    logger_.info(L"serverlist.cfg has been updated successfully.");
                } else {
                    logger_.error(L"Failed to download the new file. Using the existing local version if available.");
                }
            } else {
                logger_.info(L"File is up to date.");
            }
        } else {
            logger_.warn(L"Could not fetch remote version info. Using the existing local version if available.");
        }
    }

    std::string generateHttpResponse(const std::string& content, FILETIME last_modified_ft) {
        std::string etag = calculateHash(RESPONSE_FILENAME, BCRYPT_MD5_ALGORITHM).value_or("0");
        
        std::ostringstream response_stream;
        response_stream << "HTTP/1.1 200 OK\r\n"
                        << "Content-Type: binary/octet-stream\r\n"
                        << "Connection: keep-alive\r\n"
                        << "Date: " << getGmtTimeString(std::nullopt) << "\r\n"
                        << "Last-Modified: " << getGmtTimeString(last_modified_ft) << "\r\n"
                        << "ETag: \"" << etag << "\"\r\n"
                        << "x-amz-server-side-encryption: AES256\r\n"
                        << "Accept-Ranges: bytes\r\n"
                        << "Server: AmazonS3\r\n"
                        << "X-Cache: Miss from cloudfront\r\n"
                        << "Via: 1.1 " << generateRandomHexString(16) << ".cloudfront.net (CloudFront)\r\n"
                        << "X-Amz-Cf-Pop: HEL51-P4\r\n"
                        << "X-Amz-Cf-Id: " << generateRandomHexString(22) << "==\r\n"
                        << "Content-Length: " << content.length() << "\r\n"
                        << "\r\n"
                        << content;
        return response_stream.str();
    }
};

class ServiceManager {
public:
    static void install() {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0) {
            std::wcerr << L"Failed to get module file name. Error: " << GetLastError() << std::endl;
            return;
        }

        SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (!schSCManager) {
            std::wcerr << L"Failed to open Service Control Manager. Error: " << GetLastError() << std::endl;
            return;
        }

        SC_HANDLE schService = CreateServiceW(
            schSCManager,
            SERVICE_NAME,
            SERVICE_DISPLAY_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            path,
            NULL, NULL, NULL, NULL, NULL
        );

        if (!schService) {
            std::wcerr << L"Failed to create service. Error: " << GetLastError() << std::endl;
        } else {
            std::wcout << L"Service '" << SERVICE_DISPLAY_NAME << L"' installed successfully." << std::endl;
            CloseServiceHandle(schService);
        }
        CloseServiceHandle(schSCManager);
    }

    static void uninstall() {
        SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!schSCManager) {
            std::wcerr << L"Failed to open Service Control Manager. Error: " << GetLastError() << std::endl;
            return;
        }

        SC_HANDLE schService = OpenServiceW(schSCManager, SERVICE_NAME, DELETE);
        if (!schService) {
            std::wcerr << L"Failed to open service. Error: " << GetLastError() << std::endl;
        } else {
            if (!DeleteService(schService)) {
                std::wcerr << L"Failed to delete service. Error: " << GetLastError() << std::endl;
            } else {
                std::wcout << L"Service '" << SERVICE_DISPLAY_NAME << L"' uninstalled successfully." << std::endl;
            }
            CloseServiceHandle(schService);
        }
        CloseServiceHandle(schSCManager);
    }
};

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_service_status_handle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_service_status_handle) return;

    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwServiceSpecificExitCode = 0;

    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_service_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_service_stop_event == NULL) {
        ReportSvcStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

    EventLogger logger(true);
    auto interceptor = std::make_unique<PacketInterceptor>(logger);
    g_active_interceptor = interceptor.get();
    
    interceptor->run(); 

    g_active_interceptor = nullptr;
    ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

void WINAPI ServiceCtrlHandler(DWORD dwCtrl) {
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        if (g_active_interceptor) {
            g_active_interceptor->stop();
        }
        SetEvent(g_service_stop_event);
        ReportSvcStatus(g_service_status.dwCurrentState, NO_ERROR, 0);
        break;
    default:
        break;
    }
}

void ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    static DWORD dwCheckPoint = 1;

    g_service_status.dwCurrentState = dwCurrentState;
    g_service_status.dwWin32ExitCode = dwWin32ExitCode;
    g_service_status.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING)
        g_service_status.dwControlsAccepted = 0;
    else
        g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    
    if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
        g_service_status.dwCheckPoint = 0;
    else
        g_service_status.dwCheckPoint = dwCheckPoint++;

    SetServiceStatus(g_service_status_handle, &g_service_status);
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        if (_wcsicmp(argv[1], L"install") == 0) {
            ServiceManager::install();
            return 0;
        }
        if (_wcsicmp(argv[1], L"uninstall") == 0) {
            ServiceManager::uninstall();
            return 0;
        }
    }

    SERVICE_TABLE_ENTRYW dispatch_table[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { NULL, NULL }
    };
    
    if (!StartServiceCtrlDispatcherW(dispatch_table)) {
        std::wcout << L"Running in console mode. Use 'install' or 'uninstall' to manage the service." << std::endl;
        std::wcout << L"Press Ctrl+C to stop." << std::endl << std::endl;
        
        EventLogger logger(false);
        PacketInterceptor interceptor(logger);

        SetConsoleCtrlHandler([](DWORD ctrlType) -> BOOL {
            if (ctrlType == CTRL_C_EVENT) {
                if(g_active_interceptor) {
                    g_active_interceptor->stop();
                }
                return TRUE;
            }
            return FALSE;
        }, TRUE);
        
        g_active_interceptor = &interceptor;
        interceptor.run();
        g_active_interceptor = nullptr;
    }

    return 0;
}