#include "h_side_init.h"

#include <nlohmann/json.hpp>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <ctime>
#include <algorithm>
#include <cstring>
#include <thread>
#include <chrono>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlobj.h>

using json = nlohmann::json;

namespace {

std::string base64_decode(const std::string& encoded) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(base64_chars[i])] = i;

    std::string decoded;
    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (c == '=' || c == '\n' || c == '\r') break;
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

std::string get_local_ip() {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return "127.0.0.1";

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) { WSACleanup(); return "127.0.0.1"; }

    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &server_addr.sin_addr);

    std::string ip = "127.0.0.1";
    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == 0) {
        sockaddr_in local_addr = {};
        int local_addr_len = sizeof(local_addr);
        if (getsockname(sock, reinterpret_cast<sockaddr*>(&local_addr), &local_addr_len) == 0) {
            char ip_str[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &local_addr.sin_addr, ip_str, sizeof(ip_str));
            ip = ip_str;
        }
    }

    closesocket(sock);
    WSACleanup();
    return ip;
}

std::string get_hostname() {
    char hostname[256] = {};
    gethostname(hostname, sizeof(hostname));
    return std::string(hostname);
}

std::string mask_sensitive(const std::string& s) {
    if (s.length() <= 8) return "****";
    return s.substr(0, 4) + "****" + s.substr(s.length() - 4);
}

std::string get_program_data_path() {
    char path[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, path))) {
        return std::string(path) + "\\2c2a";
    }
    return "C:\\ProgramData\\2c2a";
}

struct WinInetHandle {
    HINTERNET handle = nullptr;
    explicit WinInetHandle(HINTERNET h = nullptr) : handle(h) {}
    ~WinInetHandle() { if (handle) InternetCloseHandle(handle); }
    WinInetHandle(const WinInetHandle&) = delete;
    WinInetHandle& operator=(const WinInetHandle&) = delete;
    operator HINTERNET() const { return handle; }
    explicit operator bool() const { return handle != nullptr; }
};

} // anonymous namespace


HSideInitializer::HSideInitializer(const std::string& secret) {
    try {
        std::string decoded_str = base64_decode(secret);
        json decoded = json::parse(decoded_str);
        c_side_url_ = decoded.value("c_side_url", "");
        token_ = decoded.value("token", "");
        host_id_ = std::to_string(decoded.value("host_id", 0));
        expires_at_ = decoded.value("expires_at", "");
        hostname_ = get_hostname();
        ip_address_ = get_local_ip();
    } catch (const json::parse_error&) {
        throw std::runtime_error("Secret \u683c\u5f0f\u65e0\u6548\uff1a\u65e0\u6cd5\u89e3\u6790 JSON");
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Secret \u89e3\u7801\u5931\u8d25\uff1a") + e.what());
    }
    if (c_side_url_.empty() || token_.empty()) {
        throw std::runtime_error("Secret \u7f3a\u5c11\u5fc5\u8981\u5b57\u6bb5(c_side_url/token)");
    }
}

HSideInitializer::HttpResponse HSideInitializer::http_request(
    const std::string& method,
    const std::string& url,
    const std::string& auth_token,
    const std::string& body,
    const std::string& content_type)
{
    HttpResponse response{0, ""};

    URL_COMPONENTSA uc = {};
    uc.dwStructSize = sizeof(uc);
    char scheme[16] = {};
    char hostname[256] = {};
    char url_path[2048] = {};
    uc.lpszScheme = scheme; uc.dwSchemeLength = sizeof(scheme);
    uc.lpszHostName = hostname; uc.dwHostNameLength = sizeof(hostname);
    uc.lpszUrlPath = url_path; uc.dwUrlPathLength = sizeof(url_path);

    if (!InternetCrackUrlA(url.c_str(), 0, 0, &uc))
        throw std::runtime_error("URL \u89e3\u6790\u5931\u8d25: " + url);

    bool use_https = (std::string(scheme, uc.dwSchemeLength) == "https");

    WinInetHandle h_internet(InternetOpenA("2c2a-H-Side/1.0", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0));
    if (!h_internet) throw std::runtime_error("InternetOpenA \u5931\u8d25");

    DWORD timeout = 30000;
    InternetSetOptionA(h_internet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(h_internet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(h_internet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    WinInetHandle h_connect(InternetConnectA(h_internet, hostname, uc.nPort,
                                              nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0));
    if (!h_connect) throw std::runtime_error("InternetConnectA \u5931\u8d25");

    DWORD flags = (use_https ? INTERNET_FLAG_SECURE : 0) | INTERNET_FLAG_NO_CACHE_WRITE | 0x00000100;

    WinInetHandle h_request(HttpOpenRequestA(h_connect, method.c_str(), url_path,
                                              nullptr, nullptr, nullptr, flags, 0));
    if (!h_request) throw std::runtime_error("HttpOpenRequestA \u5931\u8d25");

    std::string headers;
    if (!auth_token.empty()) headers += "Authorization: Bearer " + auth_token + "\r\n";
    if (!content_type.empty()) headers += "Content-Type: " + content_type + "\r\n";

    const char* body_ptr = body.empty() ? nullptr : body.c_str();
    DWORD body_len = body.empty() ? 0 : static_cast<DWORD>(body.length());

    if (!HttpSendRequestA(h_request, headers.c_str(), static_cast<DWORD>(headers.length()),
                          const_cast<char*>(body_ptr), body_len)) {
        throw std::runtime_error("HttpSendRequestA \u5931\u8d25, \u9519\u8bef: " + std::to_string(GetLastError()));
    }

    DWORD status_code = 0;
    DWORD status_code_len = sizeof(status_code);
    HttpQueryInfoA(h_request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                   &status_code, &status_code_len, nullptr);
    response.status_code = static_cast<int>(status_code);

    char buffer[4096];
    DWORD bytes_read = 0;
    while (InternetReadFile(h_request, buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        response.body.append(buffer, bytes_read);
    }

    return response;
}

bool HSideInitializer::exchange_token() {
    std::cout << "\u6b63\u5728\u8fde\u63a5\u670d\u52a1\u5668...\n";
    std::cout << "  \u4e3b\u673a\u540d: " << hostname_ << "  IP: " << ip_address_ << "\n";

    std::string url = c_side_url_ + "/bootstrap/api/get_session_token/";
    const int max_retries = 3;

    for (int attempt = 0; attempt < max_retries; ++attempt) {
        try {
            HttpResponse resp = http_request("POST", url, token_);

            if (resp.status_code == 200) {
                json result = json::parse(resp.body);
                session_token_ = result.value("session_token", "");
                int expires_in = result.value("expires_in", 0);
                if (!session_token_.empty()) {
                    std::cout << "\u2713 \u4ee4\u724c\u4ea4\u6362\u6210\u529f! \u6709\u6548\u671f: " << expires_in << " \u79d2\n";
                    return true;
                }
            } else if (resp.status_code == 401) {
                std::cout << "\u2716 \u4ee4\u724c\u65e0\u6548\u6216\u5df2\u8fc7\u671f\n";
                return false;
            } else if (resp.status_code == 403) {
                std::cout << "\u2716 IP \u5730\u5740\u4e0d\u5339\u914d\n";
                return false;
            }
        } catch (const std::exception& e) {
            std::cout << "\u26a0 \u7f51\u7edc\u9519\u8bef: " << e.what() << "\n";
        }

        if (attempt < max_retries - 1) {
            int wait_sec = (attempt + 1) * 3;
            std::cout << "  " << wait_sec << " \u79d2\u540e\u91cd\u8bd5...\n";
            Sleep(wait_sec * 1000);
        }
    }

    std::cout << "\u2716 \u4ee4\u724c\u4ea4\u6362\u5931\u8d25\n";
    return false;
}

bool HSideInitializer::configure_winrm_cert() {
    std::cout << "\n\u6b63\u5728\u914d\u7f6e WinRM \u8bc1\u4e66...\n";

    std::string ps_script =
        "$cert = New-SelfSignedCertificate -DnsName '2c2a-h-side' "
        "-CertStoreLocation 'Cert:\\LocalMachine\\My' "
        "-FriendlyName '2c2a WinRM' -NotAfter (Get-Date).AddYears(5); "
        "if (-not $cert) { exit 1 }; "
        "$thumb = $cert.Thumbprint; "
        "New-Item -Path 'WSMan:\\localhost\\Listener' "
        "-Address '*' -Transport HTTPS -CertificateThumbprint $thumb "
        "-Force -ErrorAction SilentlyContinue | Out-Null; "
        "try { Enable-PSRemoting -Force -ErrorAction Stop | Out-Null } "
        "catch {}; "
        "Set-Item -Path 'WSMan:\\localhost\\Service\\Auth\\Basic' "
        "-Value $true -Force; "
        "Set-Item -Path 'WSMan:\\localhost\\Service\\AllowUnencrypted' "
        "-Value $false -Force; "
        "Write-Output $thumb";

    std::string cmd = "powershell -NoProfile -NonInteractive -Command \""
        + ps_script + "\"";

    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "  \u65e0\u6cd5\u6267\u884c PowerShell\n";
        return false;
    }

    char buffer[256] = {};
    std::string thumbprint;
    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        if (start != std::string::npos && end != std::string::npos) {
            thumbprint = line.substr(start, end - start + 1);
        }
    }
    int ret = _pclose(pipe);

    if (ret != 0 || thumbprint.empty()) {
        std::cerr << "  \u8bc1\u4e66\u521b\u5efa\u5931\u8d25\n";
        return false;
    }

    std::cout << "  \u2713 WinRM HTTPS \u8bc1\u4e66\u5df2\u914d\u7f6e\n";
    std::cout << "  \u8bc1\u4e66\u6307\u7eb9: " << thumbprint << "\n";

    std::string config_dir = get_program_data_path();
    std::string cert_path = config_dir + "\\winrm_cert_thumb.txt";
    std::ofstream f(cert_path);
    if (f.is_open()) {
        f << thumbprint;
        f.close();
    }

    return true;
}

void HSideInitializer::save_config() {
    std::string config_dir = get_program_data_path();
    CreateDirectoryA(config_dir.c_str(), nullptr);

    json config = {
        {"session_token", session_token_},
        {"host_id", host_id_},
        {"c_side_url", c_side_url_},
        {"hostname", hostname_},
        {"ip_address", ip_address_}
    };

    std::string config_path = config_dir + "\\h_side_config.json";
    std::ofstream file(config_path);
    if (file.is_open()) {
        file << config.dump(2);
        file.close();
        std::cout << "\u2713 \u914d\u7f6e\u5df2\u4fdd\u5b58: " << config_path << "\n";
    } else {
        std::cerr << "\u26a0 \u65e0\u6cd5\u4fdd\u5b58\u914d\u7f6e\u6587\u4ef6\n";
    }
}

void HSideInitializer::initialize() {
    std::cout << std::string(50, '=') << "\n";
    std::cout << "2c2a H\u7aef\u521d\u59cb\u5316\n";
    std::cout << std::string(50, '=') << "\n";

    if (!exchange_token()) return;

    if (!configure_winrm_cert()) {
        std::cout << "\u26a0 \u8bc1\u4e66\u914d\u7f6e\u5931\u8d25\uff0c\u8bf7\u624b\u52a8\u914d\u7f6e\n";
    }

    save_config();

    std::cout << std::string(50, '=') << "\n";
    std::cout << "\u2713 H\u7aef\u521d\u59cb\u5316\u5b8c\u6210!\n";
    std::cout << "  \u4f1a\u8bdd\u4ee4\u724c: " << mask_sensitive(session_token_) << "\n";
    std::cout << std::string(50, '=') << "\n";
}
