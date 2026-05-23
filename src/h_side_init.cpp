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
#include <wincrypt.h>
#include <lm.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "netapi32.lib")

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

std::string generate_random_password(int length) {
    const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    HCRYPTPROV hprov = 0;
    if (!CryptAcquireContextW(&hprov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    std::string result(length, '\0');
    BYTE buf[256] = {};
    while (length > 0) {
        DWORD to_gen = min(length, (int)sizeof(buf));
        if (!CryptGenRandom(hprov, to_gen, buf)) { CryptReleaseContext(hprov, 0); return ""; }
        for (DWORD i = 0; i < to_gen; ++i) {
            result[result.size() - length + i] = chars[buf[i] % (sizeof(chars) - 1)];
        }
        length -= to_gen;
    }
    CryptReleaseContext(hprov, 0);
    return result;
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

struct CertCtx {
    PCCERT_CONTEXT ctx = nullptr;
    explicit CertCtx(PCCERT_CONTEXT c = nullptr) : ctx(c) {}
    ~CertCtx() { if (ctx) CertFreeCertificateContext(ctx); }
    CertCtx(const CertCtx&) = delete;
    CertCtx& operator=(const CertCtx&) = delete;
    operator PCCERT_CONTEXT() const { return ctx; }
    explicit operator bool() const { return ctx != nullptr; }
};

struct CertStore {
    HCERTSTORE store = nullptr;
    explicit CertStore(HCERTSTORE s = nullptr) : store(s) {}
    ~CertStore() { if (store) CertCloseStore(store, 0); }
    CertStore(const CertStore&) = delete;
    CertStore& operator=(const CertStore&) = delete;
    operator HCERTSTORE() const { return store; }
    explicit operator bool() const { return store != nullptr; }
};

struct CryptProv {
    HCRYPTPROV handle = 0;
    explicit CryptProv(HCRYPTPROV h = 0) : handle(h) {}
    ~CryptProv() { if (handle) CryptReleaseContext(handle, 0); }
    CryptProv(const CryptProv&) = delete;
    CryptProv& operator=(const CryptProv&) = delete;
    explicit operator bool() const { return handle != 0; }
};

} // anonymous namespace


HSideInitializer::HSideInitializer(const std::string& secret, bool debug) : debug_(debug) {
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

bool HSideInitializer::create_service_account(const std::string& username, const std::string& password) {
    std::wstring w_username(username.begin(), username.end());
    std::wstring w_password(password.begin(), password.end());

    USER_INFO_1 ui = {};
    ui.usri1_name = const_cast<LPWSTR>(w_username.c_str());
    ui.usri1_password = const_cast<LPWSTR>(w_password.c_str());
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_DONT_EXPIRE_PASSWD | UF_NORMAL_ACCOUNT;

    DWORD err = 0;
    NET_API_STATUS status = NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&ui), &err);
    if (status != NERR_Success && status != NERR_UserExists) {
        std::cerr << "  \u521b\u5efa\u7528\u6237\u5931\u8d25: " << status << "\n";
        return false;
    }

    LOCALGROUP_MEMBERS_INFO_3 mi = {};
    mi.lgrmi3_domainandname = const_cast<LPWSTR>(w_username.c_str());
    status = NetLocalGroupAddMembers(nullptr, L"Administrators", 3, reinterpret_cast<LPBYTE>(&mi), 1);
    if (status != NERR_Success && status != ERROR_MEMBER_IN_ALIAS) {
        std::cerr << "  \u6dfb\u52a0\u7ba1\u7406\u5458\u7ec4\u5931\u8d25: " << status << "\n";
        return false;
    }

    return true;
}

bool HSideInitializer::configure_winrm_cert() {
    std::cout << "\n\u6b63\u5728\u914d\u7f6e WinRM \u8bc1\u4e66...\n";

    std::string config_dir = get_program_data_path();
    CreateDirectoryA(config_dir.c_str(), nullptr);

    cert_pfx_path_ = config_dir + "\\cert.pfx";
    cert_password_ = "2c2acert";

    if (debug_) {
        BOOL is_admin = IsUserAnAdmin();
        std::cout << "  [DEBUG] \u8fd0\u884c\u4e3a\u7ba1\u7406\u5458: " << (is_admin ? "\u662f" : "\u5426!") << "\n";
    }

    { HCRYPTPROV h_tmp = 0; CryptAcquireContextW(&h_tmp, L"2c2a-winrm", nullptr, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET | CRYPT_DELETEKEYSET); }
    if (debug_) std::cout << "  [DEBUG] \u5df2\u6e05\u7406\u65e7\u5bc6\u94a5\u5bb9\u5668\n";

    CryptProv crypt_prov;
    if (!CryptAcquireContextW(&crypt_prov.handle, L"2c2a-winrm", nullptr, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET)) {
        DWORD err = GetLastError();
        std::cerr << "  CryptAcquireContext \u5931\u8d25: " << err << " (0x" << std::hex << err << std::dec << ")\n";
        if (err == 0x80090016) std::cerr << "  -> \u5bc6\u94a5\u5bb9\u5668\u4e0d\u5b58\u5728/\u65e0\u6743\u9650\u521b\u5efa\n";
        if (err == 0x8009000F) std::cerr << "  -> \u5bc6\u94a5\u5bb9\u5668\u5df2\u5b58\u5728\n";
        return false;
    }
    if (debug_) std::cout << "  [DEBUG] CryptAcquireContext \u6210\u529f, handle=" << crypt_prov.handle << "\n";

    HCRYPTKEY h_key = 0;
    if (!CryptGenKey(crypt_prov.handle, AT_KEYEXCHANGE, 0x08000000 | CRYPT_EXPORTABLE, &h_key)) {
        DWORD err = GetLastError();
        std::cerr << "  CryptGenKey \u5931\u8d25: " << err << " (0x" << std::hex << err << std::dec << ")\n";
        return false;
    }
    if (debug_) std::cout << "  [DEBUG] CryptGenKey AT_KEYEXCHANGE \u6210\u529f, key=" << h_key << "\n";

    if (debug_) {
        HCRYPTPROV h_verify = 0;
        if (CryptAcquireContextW(&h_verify, L"2c2a-winrm", nullptr, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET)) {
            HCRYPTKEY h_vk = 0;
            if (CryptGetUserKey(h_verify, AT_KEYEXCHANGE, &h_vk)) {
                std::cout << "  [DEBUG] \u9a8c\u8bc1: AT_KEYEXCHANGE \u5bc6\u94a5\u5b58\u5728\n";
                CryptDestroyKey(h_vk);
            } else {
                DWORD e = GetLastError();
                std::cout << "  [DEBUG] \u9a8c\u8bc1: AT_KEYEXCHANGE \u5bc6\u94a5\u4e0d\u5b58\u5728! err=" << e << "\n";
            }
            CryptReleaseContext(h_verify, 0);
        } else {
            std::cout << "  [DEBUG] \u9a8c\u8bc1: \u65e0\u6cd5\u91cd\u65b0\u6253\u5f00\u5bc6\u94a5\u5bb9\u5668, err=" << GetLastError() << "\n";
        }
    }

    CERT_NAME_BLOB subject_issuer_blob = {};
    std::string subject_str = "CN=2c2a-h-side";
    if (!CertStrToNameA(X509_ASN_ENCODING, subject_str.c_str(), CERT_X500_NAME_STR, nullptr, nullptr, &subject_issuer_blob.cbData, nullptr)) {
        CryptDestroyKey(h_key);
        return false;
    }
    subject_issuer_blob.pbData = static_cast<BYTE*>(LocalAlloc(LMEM_FIXED, subject_issuer_blob.cbData));
    CertStrToNameA(X509_ASN_ENCODING, subject_str.c_str(), CERT_X500_NAME_STR, nullptr, subject_issuer_blob.pbData, &subject_issuer_blob.cbData, nullptr);

    CRYPT_KEY_PROV_INFO kpi = {};
    std::wstring prov_name(L"2c2a-winrm");
    kpi.pwszContainerName = const_cast<LPWSTR>(prov_name.c_str());
    kpi.pwszProvName = nullptr;
    kpi.dwProvType = PROV_RSA_FULL;
    kpi.dwFlags = CRYPT_MACHINE_KEYSET;
    kpi.cProvParam = 0;
    kpi.dwKeySpec = AT_KEYEXCHANGE;

    if (debug_) {
        std::wcout << L"  [DEBUG] KPI: Container=" << kpi.pwszContainerName
                   << L" ProvType=" << kpi.dwProvType
                   << L" Flags=0x" << std::hex << kpi.dwFlags << std::dec
                   << L" KeySpec=" << kpi.dwKeySpec << L"\n";
    }

    CRYPT_ALGORITHM_IDENTIFIER sig_algo = {};
    sig_algo.pszObjId = szOID_RSA_SHA256RSA;

    LPSTR szOidServerAuth = const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH);
    CERT_ENHKEY_USAGE ekUsage = {};
    ekUsage.cUsageIdentifier = 1;
    ekUsage.rgpszUsageIdentifier = &szOidServerAuth;

    CERT_BASIC_CONSTRAINTS2_INFO bc2 = {};
    bc2.fCA = FALSE;
    bc2.fPathLenConstraint = FALSE;

    CRYPT_DATA_BLOB bc_blob = {};
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                             X509_BASIC_CONSTRAINTS2,
                             &bc2, 0, nullptr, nullptr, &bc_blob.cbData)) {
        CryptDestroyKey(h_key);
        LocalFree(subject_issuer_blob.pbData);
        return false;
    }
    bc_blob.pbData = static_cast<BYTE*>(LocalAlloc(LMEM_FIXED, bc_blob.cbData));
    CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        X509_BASIC_CONSTRAINTS2,
                        &bc2, 0, nullptr, bc_blob.pbData, &bc_blob.cbData);

    CERT_EXTENSION extensions[2] = {};
    extensions[0].pszObjId = szOID_ENHANCED_KEY_USAGE;
    extensions[0].fCritical = TRUE;
    extensions[0].Value.cbData = 0;
    extensions[0].Value.pbData = nullptr;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, szOID_ENHANCED_KEY_USAGE,
                             &ekUsage, 0, nullptr, nullptr, &extensions[0].Value.cbData)) {
        LocalFree(bc_blob.pbData);
        CryptDestroyKey(h_key);
        LocalFree(subject_issuer_blob.pbData);
        return false;
    }
    extensions[0].Value.pbData = static_cast<BYTE*>(LocalAlloc(LMEM_FIXED, extensions[0].Value.cbData));
    CryptEncodeObjectEx(X509_ASN_ENCODING, szOID_ENHANCED_KEY_USAGE,
                        &ekUsage, 0, nullptr, extensions[0].Value.pbData, &extensions[0].Value.cbData);

    extensions[1].pszObjId = szOID_BASIC_CONSTRAINTS2;
    extensions[1].fCritical = TRUE;
    extensions[1].Value = bc_blob;

    CERT_EXTENSIONS cert_exts = {};
    cert_exts.cExtension = 2;
    cert_exts.rgExtension = extensions;

    SYSTEMTIME st_not_before = {};
    GetSystemTime(&st_not_before);
    SYSTEMTIME st_not_after = st_not_before;
    st_not_after.wYear += 5;

    if (debug_) {
        std::cout << "  [DEBUG] \u5c1d\u8bd5 CertCreateSelfSignCertificate (pKeyProvInfo=\u975e\u7a7a)...\n";
    }

    PCCERT_CONTEXT raw_cert = CertCreateSelfSignCertificate(
        crypt_prov.handle,
        &subject_issuer_blob,
        0,
        &kpi,
        &sig_algo,
        &st_not_before,
        &st_not_after,
        &cert_exts
    );

    if (!raw_cert) {
        DWORD err = GetLastError();
        std::cerr << "  CertCreateSelfSignCertificate \u5931\u8d25(pKeyProvInfo\u975e\u7a7a): " << err << " (0x" << std::hex << err << std::dec << ")\n";

        if (debug_) {
            std::cout << "  [DEBUG] \u5c1d\u8bd5\u5907\u7528\u65b9\u6848: pKeyProvInfo=NULL ...\n";
        }

        raw_cert = CertCreateSelfSignCertificate(
            crypt_prov.handle,
            &subject_issuer_blob,
            0,
            nullptr,
            &sig_algo,
            &st_not_before,
            &st_not_after,
            &cert_exts
        );

        if (!raw_cert) {
            DWORD err2 = GetLastError();
            std::cerr << "  CertCreateSelfSignCertificate \u5931\u8d25(pKeyProvInfo=NULL): " << err2 << " (0x" << std::hex << err2 << std::dec << ")\n";
            LocalFree(subject_issuer_blob.pbData);
            CryptDestroyKey(h_key);
            LocalFree(extensions[0].Value.pbData);
            LocalFree(bc_blob.pbData);
            return false;
        }

        if (debug_) {
            std::cout << "  [DEBUG] \u5907\u7528\u65b9\u6848\u6210\u529f, \u624b\u52a8\u8bbe\u7f6e CERT_KEY_PROV_INFO_PROP_ID\n";
        }

        CRYPT_DATA_BLOB kpi_blob = {};
        kpi_blob.cbData = sizeof(CRYPT_KEY_PROV_INFO);
        kpi_blob.pbData = reinterpret_cast<BYTE*>(&kpi);
        if (!CertSetCertificateContextProperty(raw_cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi_blob)) {
            DWORD perr = GetLastError();
            std::cerr << "  \u26a0 CertSetCertificateContextProperty \u5931\u8d25: " << perr << "\n";
        }
    }

    CertCtx cert(raw_cert);
    LocalFree(subject_issuer_blob.pbData);
    CryptDestroyKey(h_key);
    LocalFree(extensions[0].Value.pbData);
    LocalFree(bc_blob.pbData);

    if (debug_) {
        std::cout << "  [DEBUG] \u8bc1\u4e66\u521b\u5efa\u6210\u529f\n";
    }

    char thumbprint_str[256] = {};
    DWORD thumbprint_len = sizeof(thumbprint_str);
    if (!CertGetCertificateContextProperty(cert, CERT_HASH_PROP_ID, thumbprint_str, &thumbprint_len)) {
        std::cerr << "  \u65e0\u6cd5\u83b7\u53d6\u8bc1\u4e66\u6307\u7eb9\n";
        return false;
    }
    std::string thumbprint_hex;
    const char hex_chars[] = "0123456789ABCDEF";
    for (DWORD i = 0; i < thumbprint_len; i++) {
        thumbprint_hex += hex_chars[(thumbprint_str[i] >> 4) & 0x0F];
        thumbprint_hex += hex_chars[thumbprint_str[i] & 0x0F];
    }

    CertStore my_store(CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, "MY"));
    if (my_store) CertAddCertificateContextToStore(my_store, cert, CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    else if (debug_) std::cout << "  [DEBUG] \u65e0\u6cd5\u6253\u5f00 MY \u5b58\u50a8\u533a\n";

    CertStore root_store(CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, "Root"));
    if (root_store) CertAddCertificateContextToStore(root_store, cert, CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    else if (debug_) std::cout << "  [DEBUG] \u65e0\u6cd5\u6253\u5f00 Root \u5b58\u50a8\u533a\n";

    CertStore tp_store(CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, "TrustedPeople"));
    if (tp_store) CertAddCertificateContextToStore(tp_store, cert, CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
    else if (debug_) std::cout << "  [DEBUG] \u65e0\u6cd5\u6253\u5f00 TrustedPeople \u5b58\u50a8\u533a\n";

    std::cout << "  \u2713 \u8bc1\u4e66\u521b\u5efa\u6210\u529f\n";
    std::cout << "  \u8bc1\u4e66\u6307\u7eb9: " << thumbprint_hex << "\n";

    CertStore pfx_store(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr));
    if (!pfx_store) {
        std::cerr << "  \u521b\u5efa PFX \u5b58\u50a8\u5931\u8d25\n";
        return false;
    }
    CertAddCertificateContextToStore(pfx_store, cert, CERT_STORE_ADD_REPLACE_EXISTING, nullptr);

    CRYPT_DATA_BLOB pfx_blob = {};
    std::wstring w_pfx_pwd(cert_password_.begin(), cert_password_.end());
    if (!PFXExportCertStoreEx(pfx_store, &pfx_blob, w_pfx_pwd.c_str(), nullptr, EXPORT_PRIVATE_KEYS)) {
        DWORD pfx_err = GetLastError();
        std::cerr << "  PFX \u5bfc\u51fa\u5931\u8d25: " << pfx_err << " (0x" << std::hex << pfx_err << std::dec << ")\n";
        if (debug_) std::cout << "  [DEBUG] \u53ef\u80fd\u662f\u79c1\u94a5\u672a\u6b63\u786e\u5173\u8054\u5230\u8bc1\u4e66\n";
        return false;
    }
    pfx_blob.pbData = static_cast<BYTE*>(LocalAlloc(LMEM_FIXED, pfx_blob.cbData));
    if (!PFXExportCertStoreEx(pfx_store, &pfx_blob, w_pfx_pwd.c_str(), nullptr, EXPORT_PRIVATE_KEYS)) {
        LocalFree(pfx_blob.pbData);
        std::cerr << "  PFX \u5bfc\u51fa\u5931\u8d25\n";
        return false;
    }

    std::ofstream pfx_file(cert_pfx_path_, std::ios::binary);
    if (pfx_file.is_open()) {
        pfx_file.write(reinterpret_cast<const char*>(pfx_blob.pbData), pfx_blob.cbData);
        pfx_file.close();
        std::cout << "  \u2713 PFX \u5df2\u5bfc\u51fa\n";
    }
    LocalFree(pfx_blob.pbData);

    std::string svc_user = "2c2a-service";
    std::string svc_pwd = generate_random_password(32);
    if (svc_pwd.empty()) {
        std::cerr << "  \u751f\u6210\u5bc6\u7801\u5931\u8d25\n";
        return false;
    }

    if (!create_service_account(svc_user, svc_pwd)) {
        std::cerr << "  \u521b\u5efa\u670d\u52a1\u8d26\u6237\u5931\u8d25\n";
        return false;
    }
    std::cout << "  \u2713 \u670d\u52a1\u8d26\u6237: " << svc_user << "\n";

    std::string ps_script =
        "try { Enable-PSRemoting -Force -ErrorAction Stop | Out-Null } catch {}; "
        "New-Item -Path 'WSMan:\\localhost\\Listener' "
        "-Address '*' -Transport HTTPS -CertificateThumbprint '" + thumbprint_hex + "' "
        "-Force -ErrorAction SilentlyContinue | Out-Null; "
        "Set-Item -Path 'WSMan:\\localhost\\Service\\Auth\\ClientCertificate' -Value $true -Force; "
        "Set-Item -Path 'WSMan:\\localhost\\Service\\Auth\\Basic' -Value $true -Force; "
        "Set-Item -Path 'WSMan:\\localhost\\Service\\AllowUnencrypted' -Value $false -Force; "
        "$secPwd = ConvertTo-SecureString -String '" + svc_pwd + "' -Force -AsPlainText; "
        "$cred = New-Object System.Management.Automation.PSCredential('" + svc_user + "',$secPwd); "
        "New-Item -Path WSMan:\\localhost\\ClientCertificate -Subject '2c2a-h-side' "
        "-Issuer '" + thumbprint_hex + "' -URI * -Credential $cred -Force -ErrorAction SilentlyContinue";

    std::string cmd = "powershell -NoProfile -NonInteractive -Command \"" + ps_script + "\"";
    int ps_ret = system(cmd.c_str());
    if (ps_ret != 0) {
        std::cerr << "  \u26a0 WinRM \u914d\u7f6e\u53ef\u80fd\u672a\u5b8c\u5168\u6210\u529f\n";
    }

    std::string thumb_path = config_dir + "\\winrm_cert_thumb.txt";
    std::ofstream tf(thumb_path);
    if (tf.is_open()) { tf << thumbprint_hex; tf.close(); }

    std::string cred_path = config_dir + "\\winrm_credentials.txt";
    std::ofstream cf(cred_path);
    if (cf.is_open()) { cf << svc_user << "\n" << svc_pwd; cf.close(); }

    std::cout << "  \u2713 WinRM HTTPS \u5df2\u914d\u7f6e\n";
    return true;
}

bool HSideInitializer::upload_cert_to_server() {
    if (cert_pfx_path_.empty()) return false;

    std::cout << "\n\u6b63\u5728\u4e0a\u4f20\u8bc1\u4e66\u5230\u670d\u52a1\u5668...\n";

    std::ifstream pfx_file(cert_pfx_path_, std::ios::binary);
    if (!pfx_file.is_open()) {
        std::cerr << "  \u65e0\u6cd5\u8bfb\u53d6 PFX \u6587\u4ef6\n";
        return false;
    }
    std::vector<char> pfx_data((std::istreambuf_iterator<char>(pfx_file)),
                                std::istreambuf_iterator<char>());
    pfx_file.close();

    DWORD b64_len = 0;
    CryptBinaryToStringA(
        reinterpret_cast<const BYTE*>(pfx_data.data()),
        static_cast<DWORD>(pfx_data.size()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        nullptr, &b64_len
    );
    std::string pfx_b64(b64_len, '\0');
    CryptBinaryToStringA(
        reinterpret_cast<const BYTE*>(pfx_data.data()),
        static_cast<DWORD>(pfx_data.size()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        &pfx_b64[0], &b64_len
    );
    pfx_b64.resize(strlen(pfx_b64.c_str()));

    std::string cred_path = get_program_data_path() + "\\winrm_credentials.txt";
    std::string svc_user, svc_pwd;
    std::ifstream cf(cred_path);
    if (cf.is_open()) {
        std::getline(cf, svc_user);
        std::getline(cf, svc_pwd);
        cf.close();
    }

    json payload = {
        {"token", token_},
        {"pfx_b64", pfx_b64},
        {"pfx_password", cert_password_},
        {"service_user", svc_user},
        {"service_password", svc_pwd},
    };

    try {
        std::string url = c_side_url_ + "/bootstrap/api/upload_host_cert/";
        HttpResponse resp = http_request("POST", url, "", payload.dump(), "application/json");

        if (resp.status_code == 200) {
            json result = json::parse(resp.body);
            if (result.value("success", false)) {
                std::cout << "  \u2713 \u8bc1\u4e66\u5df2\u4e0a\u4f20\u5230\u670d\u52a1\u5668\n";
                DeleteFileA(cert_pfx_path_.c_str());
                return true;
            }
        }
        std::cerr << "  \u8bc1\u4e66\u4e0a\u4f20\u5931\u8d25\n";
        return false;
    } catch (const std::exception& e) {
        std::cerr << "  \u4e0a\u4f20\u9519\u8bef: " << e.what() << "\n";
        return false;
    }
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
    } else {
        upload_cert_to_server();
    }

    save_config();

    std::cout << std::string(50, '=') << "\n";
    std::cout << "\u2713 H\u7aef\u521d\u59cb\u5316\u5b8c\u6210!\n";
    std::cout << "  \u4f1a\u8bdd\u4ee4\u724c: " << mask_sensitive(session_token_) << "\n";
    std::cout << std::string(50, '=') << "\n";
}
