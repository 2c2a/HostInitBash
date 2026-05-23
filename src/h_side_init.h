#pragma once

#include <string>

class HSideInitializer {
public:
    explicit HSideInitializer(const std::string& secret);

    void initialize();

private:
    std::string c_side_url_;
    std::string token_;
    std::string host_id_;
    std::string expires_at_;
    std::string hostname_;
    std::string ip_address_;
    std::string session_token_;

    struct HttpResponse {
        int status_code;
        std::string body;
    };

    HttpResponse http_request(const std::string& method,
                              const std::string& url,
                              const std::string& auth_token = "",
                              const std::string& body = "",
                              const std::string& content_type = "application/json");

    bool exchange_token();
    bool create_service_account(const std::string& username, const std::string& password);
    bool configure_winrm_cert();
    bool upload_cert_to_server();
    void save_config();

    std::string cert_pfx_path_;
    std::string cert_password_;
};
