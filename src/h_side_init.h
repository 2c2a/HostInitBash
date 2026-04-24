#pragma once

#include <string>

class HSideInitializer {
public:
    explicit HSideInitializer(const std::string& secret);

    void initialize();
    void print_info() const;

private:
    std::string c_side_url_;
    std::string token_;
    std::string host_id_;
    std::string expires_at_;
    std::string hostname_;
    std::string ip_address_;

    std::string derive_totp_key();
    std::string generate_and_display_totp();
    std::string exchange_token();
    void save_session_token(const std::string& session_token);
    std::string activate_with_totp();
};
