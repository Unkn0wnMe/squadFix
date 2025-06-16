#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <optional>
#include <stdexcept>

#include <windows.h>
#include <wininet.h>
#include <bcrypt.h>
#include "windivert.h"

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")

const std::wstring GITHUB_USER = L"Unkn0wnMe";
const std::wstring GITHUB_REPO = L"squadFix";
const std::wstring GITHUB_BRANCH = L"master";

const char* TARGET_HOST = "game-files.offworldindustries.com";
const char* TARGET_PATH = "/squad/serverlist.cfg";
const char* RESPONSE_FILENAME = "serverlist.cfg";
constexpr size_t MAX_TCP_PAYLOAD = 1400; // Safe MTU size


class InternetHandle {
    HINTERNET handle_ = NULL;
public:
    InternetHandle(HINTERNET h) : handle_(h) {}
    ~InternetHandle() { if (handle_) InternetCloseHandle(handle_); }
    operator HINTERNET() const { return handle_; }
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


void SetConsoleColor(WORD color) {
    SetStdHandle(STD_OUTPUT_HANDLE, GetStdHandle(STD_OUTPUT_HANDLE));
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

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

std::optional<std::string> calculateSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return std::nullopt;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        return std::nullopt;
    }
    auto closeAlgProvider = [](BCRYPT_ALG_HANDLE h) { BCryptCloseAlgorithmProvider(h, 0); };
    std::unique_ptr<void, decltype(closeAlgProvider)> algGuard(hAlg, closeAlgProvider);

    DWORD cbHashObject = 0, cbData = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
        return std::nullopt;
    }
    std::vector<BYTE> pHashObject(cbHashObject);

    BCRYPT_HASH_HANDLE hHash = NULL;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pHashObject.data(), cbHashObject, NULL, 0, 0))) {
        return std::nullopt;
    }
    BcryptHandle<void> hashGuard(hHash, BCryptDestroyHash);

    std::vector<char> buffer(4096);
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        if (file.gcount() > 0) {
            if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PBYTE)buffer.data(), (ULONG)file.gcount(), 0))) {
                return std::nullopt;
            }
        }
    }

    constexpr DWORD cbHash = 32;
    std::vector<BYTE> pHash(cbHash);
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, pHash.data(), cbHash, 0))) {
        return std::nullopt;
    }

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& b : pHash) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

void PerformUpdate(WORD default_color, WORD color_info, WORD color_success, WORD color_error, WORD color_target) {
    SetConsoleColor(color_info);
    std::wcout << L"Checking for " << RESPONSE_FILENAME << " updates from " << GITHUB_USER << L"/" << GITHUB_REPO << "..." << std::endl;
    SetConsoleColor(default_color);

    std::wstring sha_url = L"https://raw.githubusercontent.com/" + GITHUB_USER + L"/" + GITHUB_REPO + L"/" + GITHUB_BRANCH + L"/serverlist.cfg.sha";
    auto remote_sha_opt = downloadFile(sha_url);

    if (remote_sha_opt) {
        std::string remote_sha = *remote_sha_opt;
        remote_sha.erase(std::remove_if(remote_sha.begin(), remote_sha.end(), ::isspace), remote_sha.end());
        std::transform(remote_sha.begin(), remote_sha.end(), remote_sha.begin(), ::tolower);

        auto local_sha_opt = calculateSHA256(RESPONSE_FILENAME);
        std::string local_sha = local_sha_opt.value_or("");

        if (local_sha != remote_sha) {
            SetConsoleColor(color_target);
            std::cout << (local_sha.empty() ? "Local file not found." : "New version available.") << " Downloading..." << std::endl;
            SetConsoleColor(default_color);

            std::wstring file_url = L"https://raw.githubusercontent.com/" + GITHUB_USER + L"/" + GITHUB_REPO + L"/" + GITHUB_BRANCH + L"/serverlist.cfg";
            auto new_content_opt = downloadFile(file_url);

            if (new_content_opt) {
                std::ofstream out_file(RESPONSE_FILENAME, std::ios::binary);
                out_file << *new_content_opt;
                out_file.close();
                SetConsoleColor(color_success);
                std::cout << RESPONSE_FILENAME << " has been updated successfully." << std::endl;
            } else {
                SetConsoleColor(color_error);
                std::cerr << "Failed to download the new file. Using the existing local version if available." << std::endl;
            }
        } else {
            SetConsoleColor(color_success);
            std::cout << "File is up to date." << std::endl;
        }
    } else {
        SetConsoleColor(color_error);
        std::cerr << "Could not fetch remote version info. Using the existing local version if available." << std::endl;
    }
    SetConsoleColor(default_color);
    std::cout << std::endl;
}

int main() {
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &consoleInfo);
    const WORD DEFAULT_COLOR = consoleInfo.wAttributes;
    const WORD COLOR_INFO = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    const WORD COLOR_SUCCESS = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    const WORD COLOR_ERROR = FOREGROUND_RED | FOREGROUND_INTENSITY;
    const WORD COLOR_TARGET = FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;

    PerformUpdate(DEFAULT_COLOR, COLOR_INFO, COLOR_SUCCESS, COLOR_ERROR, COLOR_TARGET);

    std::string response_file_content;
    {
        std::ifstream file_stream(RESPONSE_FILENAME, std::ios::binary);
        if (!file_stream) {
            SetConsoleColor(COLOR_ERROR);
            std::cerr << "FATAL: Cannot open " << RESPONSE_FILENAME << ". The program cannot function without it. Exiting." << std::endl;
            SetConsoleColor(DEFAULT_COLOR);
            std::cout << "Press Enter to exit...";
            std::cin.get();
            return 1;
        }
        std::stringstream buffer;
        buffer << file_stream.rdbuf();
        response_file_content = buffer.str();
    }
    
    std::string full_http_response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: binary/octet-stream\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: " + std::to_string(response_file_content.length()) + "\r\n"
        "\r\n" 
        + response_file_content;
    
    const char* filter = "outbound and tcp.DstPort == 80";
    WinDivertHandle handle(filter, WINDIVERT_LAYER_NETWORK, 0, 0);

    if (!handle.isValid()) {
        SetConsoleColor(COLOR_ERROR);
        std::cerr << "Error: Failed to open WinDivert. Make sure it is installed and the program is run with Administrator privileges." << std::endl;
        std::cerr << "WinDivert error code: " << GetLastError() << std::endl;
        SetConsoleColor(DEFAULT_COLOR);
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    SetConsoleColor(COLOR_SUCCESS);
    std::cout << "WinDivert opened successfully." << std::endl;
    SetConsoleColor(COLOR_INFO);
    std::cout << "Listening for Squad HTTP requests..." << std::endl;
    std::cout << "Target: GET http://" << TARGET_HOST << TARGET_PATH << std::endl;
    SetConsoleColor(DEFAULT_COLOR);
    std::cout << "Press Ctrl+C to stop." << std::endl << std::endl;

    char packet[WINDIVERT_MTU_MAX];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    while (true) {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr)) {
            SetConsoleColor(COLOR_ERROR);
            std::cerr << "Error: Failed to receive packet (error " << GetLastError() << "). Exiting." << std::endl;
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
            SetConsoleColor(COLOR_TARGET);
            std::cout << "Target request intercepted! Sending emulated response from " << RESPONSE_FILENAME << "..." << std::endl;
            SetConsoleColor(DEFAULT_COLOR);

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
                     SetConsoleColor(COLOR_ERROR);
                     std::cerr << "Failed to send chunk " << (bytes_sent / MAX_TCP_PAYLOAD + 1) << ". Error: " << GetLastError() << std::endl;
                     SetConsoleColor(DEFAULT_COLOR);
                     break;
                }

                bytes_sent += chunk_size;
            }
            std::cout << "Response sent in " << (bytes_sent / MAX_TCP_PAYLOAD + 1) << " chunks." << std::endl << std::endl;
            continue;
        }
        WinDivertSend(handle, packet, packet_len, NULL, &addr);
    }
    return 0;
}