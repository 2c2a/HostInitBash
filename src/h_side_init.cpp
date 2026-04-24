#include "h_side_init.h"

#include <nlohmann/json.hpp>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <thread>
#include <chrono>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <bcrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>

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

std::string base32_encode(const std::vector<uint8_t>& data) {
    static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    std::string encoded;
    int val = 0, valb = 0;

    for (uint8_t c : data) {
        val = (val << 8) | c;
        valb += 8;
        while (valb >= 5) {
            valb -= 5;
            encoded.push_back(base32_chars[(val >> valb) & 0x1F]);
        }
    }

    if (valb > 0) {
        encoded.push_back(base32_chars[(val << (5 - valb)) & 0x1F]);
    }

    while (encoded.size() % 8 != 0) {
        encoded.push_back('=');
    }

    return encoded;
}

std::vector<uint8_t> base32_decode(const std::string& encoded) {
    static const int T[] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        14, 11, 26, 27, 28, 29, 30, 31,  1,  2,  3, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    };

    std::vector<uint8_t> decoded;
    int val = 0, valb = 0;

    for (char c : encoded) {
        if (c == '=') break;
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= sizeof(T) / sizeof(T[0]) || T[uc] == -1) continue;
        val = (val << 5) | T[uc];
        valb += 5;
        if (valb >= 8) {
            valb -= 8;
            decoded.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
        }
    }

    return decoded;
}

std::vector<uint8_t> hmac_sha(LPCWSTR algorithm,
                               const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& message) {
    BCRYPT_ALG_HANDLE h_alg = nullptr;
    BCRYPT_HASH_HANDLE h_hash = nullptr;
    DWORD hash_len = 0;
    DWORD result_len = 0;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, algorithm, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

    status = BCryptGetProperty(h_alg, BCRYPT_HASH_LENGTH,
                               reinterpret_cast<PUCHAR>(&hash_len), sizeof(DWORD), &result_len, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        throw std::runtime_error("BCryptGetProperty failed");
    }

    std::vector<uint8_t> hash_result(hash_len);

    status = BCryptCreateHash(h_alg, &h_hash, nullptr, 0,
                              const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        throw std::runtime_error("BCryptCreateHash failed");
    }

    status = BCryptHashData(h_hash, const_cast<PUCHAR>(message.data()), static_cast<ULONG>(message.size()), 0);
    if (status != 0) {
        BCryptDestroyHash(h_hash);
        BCryptCloseAlgorithmProvider(h_alg, 0);
        throw std::runtime_error("BCryptHashData failed");
    }

    status = BCryptFinishHash(h_hash, hash_result.data(), hash_len, 0);
    if (status != 0) {
        BCryptDestroyHash(h_hash);
        BCryptCloseAlgorithmProvider(h_alg, 0);
        throw std::runtime_error("BCryptFinishHash failed");
    }

    BCryptDestroyHash(h_hash);
    BCryptCloseAlgorithmProvider(h_alg, 0);

    return hash_result;
}

struct HttpResponse {
    int status_code;
    std::string body;
};

HttpResponse http_post(const std::string& url, const std::string& auth_token) {
    HttpResponse response{0, ""};

    URL_COMPONENTSA uc = {};
    uc.dwStructSize = sizeof(uc);

    char scheme[16] = {};
    char hostname[256] = {};
    char url_path[2048] = {};

    uc.lpszScheme = scheme;
    uc.dwSchemeLength = sizeof(scheme);
    uc.lpszHostName = hostname;
    uc.dwHostNameLength = sizeof(hostname);
    uc.lpszUrlPath = url_path;
    uc.dwUrlPathLength = sizeof(url_path);

    if (!InternetCrackUrlA(url.c_str(), 0, 0, &uc)) {
        throw std::runtime_error("Failed to parse URL: " + url);
    }

    bool use_https = (std::string(scheme, uc.dwSchemeLength) == "https");

    HINTERNET h_internet = InternetOpenA("ZASCA-H-Side/1.0", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!h_internet) throw std::runtime_error("InternetOpenA failed");

    DWORD timeout = 30000;
    InternetSetOptionA(h_internet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(h_internet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(h_internet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    HINTERNET h_connect = InternetConnectA(h_internet, hostname, uc.nPort,
                                           nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!h_connect) {
        InternetCloseHandle(h_internet);
        throw std::runtime_error("InternetConnectA failed");
    }

    DWORD flags = (use_https ? INTERNET_FLAG_SECURE : 0) |
                  INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NO_CACHE;

    HINTERNET h_request = HttpOpenRequestA(h_connect, "POST", url_path,
                                           nullptr, nullptr, nullptr, flags, 0);
    if (!h_request) {
        InternetCloseHandle(h_connect);
        InternetCloseHandle(h_internet);
        throw std::runtime_error("HttpOpenRequestA failed");
    }

    std::string headers = "Authorization: Bearer " + auth_token + "\r\nContent-Type: application/json\r\n";

    if (!HttpSendRequestA(h_request, headers.c_str(), static_cast<DWORD>(headers.length()), nullptr, 0)) {
        DWORD err = GetLastError();
        InternetCloseHandle(h_request);
        InternetCloseHandle(h_connect);
        InternetCloseHandle(h_internet);
        throw std::runtime_error("HttpSendRequestA failed, error: " + std::to_string(err));
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

    InternetCloseHandle(h_request);
    InternetCloseHandle(h_connect);
    InternetCloseHandle(h_internet);

    return response;
}

std::string get_local_ip() {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return "127.0.0.1";
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return "127.0.0.1";
    }

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

std::string generate_totp(const std::string& k_totp, int digits, int interval) {
    std::vector<uint8_t> key = base32_decode(k_totp);

    time_t now = time(nullptr);
    uint64_t counter = static_cast<uint64_t>(now) / interval;

    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; --i) {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    std::vector<uint8_t> msg(counter_bytes, counter_bytes + 8);
    std::vector<uint8_t> hmac_result = hmac_sha(BCRYPT_SHA1_ALGORITHM, key, msg);

    int offset = hmac_result[hmac_result.size() - 1] & 0x0F;
    uint32_t binary =
        ((hmac_result[offset] & 0x7F) << 24) |
        ((hmac_result[offset + 1] & 0xFF) << 16) |
        ((hmac_result[offset + 2] & 0xFF) << 8) |
        (hmac_result[offset + 3] & 0xFF);

    uint32_t otp = binary % 1000000;

    std::ostringstream oss;
    oss << std::setw(digits) << std::setfill('0') << otp;
    return oss.str();
}

int get_time_remaining(int interval) {
    time_t now = time(nullptr);
    return interval - (static_cast<int>(now) % interval);
}

} // anonymous namespace


HSideInitializer::HSideInitializer(const std::string& secret) {
    std::string decoded_str = base64_decode(secret);
    json decoded = json::parse(decoded_str);

    c_side_url_ = decoded.value("c_side_url", "");
    token_ = decoded.value("token", "");
    host_id_ = decoded.value("host_id", "");
    expires_at_ = decoded.value("expires_at", "");
    hostname_ = get_hostname();
    ip_address_ = get_local_ip();
}

std::string HSideInitializer::derive_totp_key() {
    const std::string SHARED_STATIC_SALT = "MY_SECRET_2024";

    std::string input_string = token_ + "|" + host_id_ + "|" + expires_at_;

    std::vector<uint8_t> key(SHARED_STATIC_SALT.begin(), SHARED_STATIC_SALT.end());
    std::vector<uint8_t> msg(input_string.begin(), input_string.end());

    std::vector<uint8_t> raw_hash = hmac_sha(BCRYPT_SHA256_ALGORITHM, key, msg);

    std::vector<uint8_t> truncated_hash(raw_hash.begin(), raw_hash.begin() + 20);
    return base32_encode(truncated_hash);
}

std::string HSideInitializer::generate_and_display_totp() {
    std::string k_totp = derive_totp_key();
    std::string current_code = generate_totp(k_totp, 6, 30);

    std::cout << std::string(60, '=') << "\n";
    std::cout << "ZASCA H\u7aef\u521d\u59cb\u5316 - TOTP\u9a8c\u8bc1\u9636\u6bb5\n";
    std::cout << "\u4e3b\u673aID: " << host_id_ << "\n";
    std::cout << "\u4e3b\u673a\u540d: " << hostname_ << "\n";
    std::cout << "IP\u5730\u5740: " << ip_address_ << "\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "\u8bf7\u8bbf\u95ee C \u7aef\u7ba1\u7406\u540e\u53f0\uff0c\u8f93\u5165\u4e3b\u673a ID [" << host_id_
              << "] \u548c\u9a8c\u8bc1\u7801 [" << current_code << "] \u8fdb\u884c\u6fc0\u6d3b\n";
    std::cout << "\u6fc0\u6d3b\u5b8c\u6210\u540e\u6309\u56de\u8f66\u952e\u7ee7\u7eed...\n";

    int time_remaining = get_time_remaining(30);
    std::cout << "\u5f53\u524d\u9a8c\u8bc1\u7801\u5269\u4f59\u6709\u6548\u65f6\u95f4: " << time_remaining << "\u79d2\n";

    std::cin.get();

    return current_code;
}

std::string HSideInitializer::exchange_token() {
    std::cout << "\u6b63\u5728\u5411C\u7aef\u53d1\u8d77token\u4ea4\u6362\u8bf7\u6c42...\n";

    std::string url = c_side_url_ + "/api/exchange_token";

    const int max_retries = 3;
    int retry_count = 0;

    while (retry_count < max_retries) {
        try {
            HttpResponse resp = http_post(url, token_);

            if (resp.status_code == 200) {
                json result = json::parse(resp.body);
                std::string session_token = result.value("session_token", "");
                int expires_in = result.value("expires_in", 0);

                std::cout << "\u2713 Token\u4ea4\u6362\u6210\u529f!\n";
                std::cout << "  \u4f1a\u8bdd\u4ee4\u724c: " << session_token << "\n";
                std::cout << "  \u6709\u6548\u671f: " << expires_in << "\u79d2\n";

                save_session_token(session_token);

                return session_token;

            } else if (resp.status_code == 400) {
                if (resp.body.find("Wait To Active") != std::string::npos) {
                    std::cout << "\u26a0 \u72b6\u6001: \u7b49\u5f85\u6fc0\u6d3b\uff0c\u8bf7\u786e\u8ba4\u5df2\u5728C\u7aef\u5b8c\u6210TOTP\u9a8c\u8bc1\n";
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    retry_count++;
                    continue;
                } else {
                    std::cout << "\u2716 \u8bf7\u6c42\u9519\u8bef (400): " << resp.body << "\n";
                    break;
                }

            } else if (resp.status_code == 403) {
                std::cout << "\u2716 \u8bbf\u95ee\u88ab\u62d2\u7edd (403): \u8bf7\u68c0\u67e5TOTP\u662f\u5426\u8f93\u5165\u6b63\u786e\uff0c\u6216Base64\u662f\u5426\u6709\u6548\n";
                break;

            } else {
                std::cout << "\u2716 \u8bf7\u6c42\u5931\u8d25\uff0c\u72b6\u6001\u7801: " << resp.status_code << "\n";
                std::cout << "  \u54cd\u5e94: " << resp.body << "\n";
                break;
            }

        } catch (const std::exception& e) {
            std::cout << "\u26a0 \u7f51\u7edc\u8bf7\u6c42\u9519\u8bef: " << e.what() << "\n";
            break;
        }
    }

    if (retry_count >= max_retries) {
        std::cout << "\u2716 \u5df2\u8fbe\u5230\u6700\u5927\u91cd\u8bd5\u6b21\u6570\uff0cToken\u4ea4\u6362\u5931\u8d25\n";
    }

    throw std::runtime_error("Token\u4ea4\u6362\u5931\u8d25");
}

void HSideInitializer::save_session_token(const std::string& session_token) {
    json config = {
        {"session_token", session_token},
        {"host_id", host_id_},
        {"c_side_url", c_side_url_},
        {"ip_address", ip_address_}
    };

    std::ofstream file("h_side_config.json");
    if (file.is_open()) {
        file << config.dump(2);
        file.close();
        std::cout << "\u2713 \u4f1a\u8bdd\u4ee4\u724c\u5df2\u4fdd\u5b58\u5230\u672c\u5730\u914d\u7f6e\u6587\u4ef6: h_side_config.json\n";
    }
}

std::string HSideInitializer::activate_with_totp() {
    std::string totp_code = generate_and_display_totp();
    std::string session_token = exchange_token();

    std::cout << std::string(60, '=') << "\n";
    std::cout << "ZASCA H\u7aef\u521d\u59cb\u5316\u5b8c\u6210\uff01\n";
    std::cout << "\u2713 H\u7aef\u5df2\u6fc0\u6d3b\uff0c\u4f1a\u8bdd\u4ee4\u724c: " << session_token << "\n";
    std::cout << "\u2713 H\u7aef\u73b0\u5728\u5904\u4e8eZeroAgent\u72b6\u6001\uff0c\u7b49\u5f85C\u7aef\u8fde\u63a5\n";
    std::cout << std::string(60, '=') << "\n";

    return session_token;
}

void HSideInitializer::initialize() {
    std::cout << "\u5f00\u59cbZASCA H\u7aef\u521d\u59cb\u5316\u6d41\u7a0b...\n";
    activate_with_totp();
}

void HSideInitializer::print_info() const {
    std::cout << "\u4e3b\u673a\u540d: " << hostname_ << "\n";
    std::cout << "IP\u5730\u5740: " << ip_address_ << "\n";
    std::cout << "C\u7aef\u5730\u5740: " << c_side_url_ << "\n";
    std::cout << "\u4e3b\u673aID: " << host_id_ << "\n";
    std::cout << "\u8fc7\u671f\u65f6\u95f4: " << expires_at_ << "\n";
    std::cout << "\u6b64\u6a21\u5f0f\u4e0b\u5c06\u6267\u884c\u4ee5\u4e0b\u64cd\u4f5c:\n";
    std::cout << "1. \u8ba1\u7b97TOTP\u5bc6\u94a5\n";
    std::cout << "2. \u751f\u6210\u5e76\u663e\u793aTOTP\u7801\n";
    std::cout << "3. \u5411C\u7aef\u53d1\u8d77token\u4ea4\u6362\u8bf7\u6c42\n";
    std::cout << "4. \u4fdd\u5b58\u4f1a\u8bdd\u4ee4\u724c\n";
}
