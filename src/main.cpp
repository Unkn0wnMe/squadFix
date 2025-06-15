#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <iomanip>

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
const std::wstring GITHUB_BRANCH = L"main";             

const char* TARGET_HOST = "game-files.offworldindustries.com";
const char* TARGET_PATH = "/squad/serverlist.cfg";
const char* RESPONSE_FILENAME = "serverlist.cfg";

std::string downloadFile(const std::wstring& url) {
    HINTERNET hInternet = InternetOpenW(L"SquadFix-Updater", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return "";

    HINTERNET hUrl = InternetOpenUrlW(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return "";
    }

    std::string content;
    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        content.append(buffer, bytesRead);
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    return content;
}

std::string calculateSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "";

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) return "";
    
    DWORD cbHashObject = 0, cbData = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    std::vector<BYTE> pHashObject(cbHashObject);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pHashObject.data(), cbHashObject, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    std::vector<char> buffer(4096);
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        if (file.gcount() > 0) {
            BCryptHashData(hHash, (PBYTE)buffer.data(), (ULONG)file.gcount(), 0);
        }
    }

    DWORD cbHash = 32;
    std::vector<BYTE> pHash(cbHash);
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, pHash.data(), cbHash, 0))) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::stringstream ss;
    for (BYTE b : pHash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return ss.str();
}

std::string get_current_gmt_time() {
    char buf[100] = {0};
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm gmt_tm;
    gmtime_s(&gmt_tm, &now);
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &gmt_tm);
    return buf;
}

int main() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    const WORD DEFAULT_COLOR = consoleInfo.wAttributes;
    const WORD COLOR_INFO = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    const WORD COLOR_SUCCESS = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    const WORD COLOR_ERROR = FOREGROUND_RED | FOREGROUND_INTENSITY;
    const WORD COLOR_TARGET = FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;

    SetConsoleTextAttribute(hConsole, COLOR_INFO);
    std::wcout << L"Checking for " << RESPONSE_FILENAME << " updates from " << GITHUB_USER << L"/" << GITHUB_REPO << "..." << std::endl;
    SetConsoleTextAttribute(hConsole, DEFAULT_COLOR);
    
    std::wstring sha_url = L"https://raw.githubusercontent.com/" + GITHUB_USER + L"/" + GITHUB_REPO + L"/" + GITHUB_BRANCH + L"/serverlist.cfg.sha";
    std::string remote_sha = downloadFile(sha_url);
    if (!remote_sha.empty()) {
        remote_sha.erase(std::remove_if(remote_sha.begin(), remote_sha.end(), ::isspace), remote_sha.end());
        std::transform(remote_sha.begin(), remote_sha.end(), remote_sha.begin(), ::tolower);
        std::string local_sha = calculateSHA256(RESPONSE_FILENAME);

        if (local_sha != remote_sha) {
            SetConsoleTextAttribute(hConsole, COLOR_TARGET);
            std::cout << (local_sha.empty() ? "Local file not found." : "New version available.") << " Downloading..." << std::endl;
            SetConsoleTextAttribute(hConsole, DEFAULT_COLOR);

            std::wstring file_url = L"https://raw.githubusercontent.com/" + GITHUB_USER + L"/" + GITHUB_REPO + L"/" + GITHUB_BRANCH + L"/serverlist.cfg";
            std::string new_content = downloadFile(file_url);

            if (!new_content.empty()) {
                std::ofstream out_file(RESPONSE_FILENAME, std::ios::binary);
                out_file << new_content;
                out_file.close();
                SetConsoleTextAttribute(hConsole, COLOR_SUCCESS);
                std::cout << RESPONSE_FILENAME << " has been updated successfully." << std::endl;
                SetConsoleTextAttribute(hConsole, DEFAULT_COLOR);
            } else {
                SetConsoleTextAttribute(hConsole, COLOR_ERROR);
                std::cerr << "Failed to download the new file. Using the existing local version." << std::endl;
                SetConsoleTextAttribute(hConsole, DEFAULT_COLOR);
            }
        } else {
            SetConsoleTextAttribute(hConsole, COLOR_SUCCESS);
            std::cout << "File is up to date." << std::endl;
            SetConsoleTextAttribute(hConsole, DEFAULT_COLOR);
        }
    } else {
        SetConsoleTextAttribute(hConsole, COLOR_ERROR);
        std::cerr << "Could not fetch remote version info. Using the existing local version." << std::endl;
        SetConsoleTextAttribute(hConsole, DEFAULT_COLOR);
    }
    std::cout << std::endl;

    std::ifstream file_stream(RESPONSE_FILENAME);
    if (!file_stream.is_open()) {
        SetConsoleTextAttribute(hConsole, COLOR_ERROR);
        std::cerr << "Fatal Error: Cannot open " << RESPONSE_FILENAME << " after update check. Exiting." << std::endl;
        SetConsoleTextAttribute(hConsole, DEFAULT_COLOR);
        system("pause");
        return 1;
    }
    std::stringstream buffer;
    buffer << file_stream.rdbuf();
    std::string response_file_content = buffer.str();
    
    std::stringstream response_stream;
    response_stream << "HTTP/1.1 200 OK\r\n"
                    << "Server: AmazonS3\r\n"
                    << "Date: " << get_current_gmt_time() << "\r\n"
                    << "Content-Type: text/plain\r\n"
                    << "Content-Length: " << response_file_content.length() << "\r\n"
                    << "Last-Modified: Fri, 20 Dec 2024 10:00:00 GMT\r\n"
                    << "ETag: \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"\r\n"
                    << "x-amz-request-id: TXJA123BC456DE78\r\n"
                    << "x-amz-id-2: VpXqR7sFpXl9a/bCdeFgHiJkLmNoPqRsTuVwXyZ01234567890aBcDeF\r\n"
                    << "Connection: close\r\n"
                    << "\r\n"
                    << response_file_content;
    std::string full_http_response = response_stream.str();

    HANDLE handle;
    char packet[WINDIVERT_MTU_MAX];
    WINDIVERT_ADDRESS addr;
    UINT packet_len;
    const char* filter = "outbound and tcp.DstPort == 80";

    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(hConsole, COLOR_ERROR);
        std::cerr << "Error: Failed to open WinDivert device (error code: " << GetLastError() << ")." << std::endl;
        SetConsoleTextAttribute(hConsole, DEFAULT_COLOR);
        system("pause");
        return 1;
    }

    SetConsoleTextAttribute(hConsole, COLOR_SUCCESS);
    std::cout << "\nWinDivert opened successfully." << std::endl;
    SetConsoleTextAttribute(hConsole, COLOR_INFO);
    std::cout << "Listening for Squad HTTP requests..." << std::endl;
    std::cout << "Target: GET http://" << TARGET_HOST << TARGET_PATH << std::endl;
    SetConsoleTextAttribute(hConsole, DEFAULT_COLOR);
    std::cout << "Press Ctrl+C to stop." << std::endl << std::endl;

    while (TRUE) {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr)) continue;
        PWINDIVERT_IPHDR ip_header; PWINDIVERT_TCPHDR tcp_header; PVOID payload; UINT payload_len;
        WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, NULL, &tcp_header, NULL, &payload, &payload_len, NULL, NULL);
        if (tcp_header == NULL || payload == NULL || payload_len == 0) { WinDivertSend(handle, packet, packet_len, NULL, &addr); continue; }
        std::string request_str(static_cast<const char*>(payload), payload_len);
        bool is_target_request = (request_str.find(std::string("GET ") + TARGET_PATH) != std::string::npos) && (request_str.find(std::string("Host: ") + TARGET_HOST) != std::string::npos);
        if (is_target_request) {
            SetConsoleTextAttribute(hConsole, COLOR_TARGET);
            std::cout << "request intercepted! Sending emulated response from " << RESPONSE_FILENAME << "." << std::endl;
            SetConsoleTextAttribute(hConsole, DEFAULT_COLOR);
            char response_packet[WINDIVERT_MTU_MAX]; const UINT headers_len = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_TCPHDR);
            memcpy(response_packet, packet, headers_len);
            PWINDIVERT_IPHDR resp_ip_header = (PWINDIVERT_IPHDR)response_packet; PWINDIVERT_TCPHDR resp_tcp_header = (PWINDIVERT_TCPHDR)(response_packet + sizeof(WINDIVERT_IPHDR));
            std::swap(resp_ip_header->SrcAddr, resp_ip_header->DstAddr); std::swap(resp_tcp_header->SrcPort, resp_tcp_header->DstPort);
            resp_tcp_header->AckNum = htonl(ntohl(tcp_header->SeqNum) + payload_len); resp_tcp_header->SeqNum = tcp_header->AckNum;
            resp_tcp_header->Fin = 1; resp_tcp_header->Ack = 1; resp_tcp_header->Psh = 1; resp_tcp_header->Rst = 0; resp_tcp_header->Syn = 0; resp_tcp_header->Urg = 0;
            size_t response_payload_len = full_http_response.length(); memcpy((char*)response_packet + headers_len, full_http_response.c_str(), response_payload_len);
            UINT new_packet_len = headers_len + (UINT)response_payload_len;
            addr.Outbound = 0;
            WinDivertHelperCalcChecksums(response_packet, new_packet_len, &addr, 0);
            WinDivertSend(handle, response_packet, new_packet_len, NULL, &addr);
            continue;
        }
        WinDivertSend(handle, packet, packet_len, NULL, &addr);
    }

    WinDivertClose(handle);
    return 0;
}