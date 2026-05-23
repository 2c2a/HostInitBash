#include "h_side_init.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>
#include <string>
#include <cstdlib>

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    std::string secret;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: h_side_init <secret>\n";
            std::cout << "  secret  \u4ece C \u7aef\u83b7\u53d6\u7684\u52a0\u5bc6\u914d\u7f6e\u5b57\u7b26\u4e32\n";
            return 0;
        } else if (arg[0] != '-') {
            secret = arg;
        }
    }

    const char* demo_env = std::getenv("2C2A_DEMO");
    if (demo_env && std::string(demo_env) == "1") {
        std::cerr << "\u9519\u8bef: \u6b64\u7a0b\u5e8f\u4e0d\u80fd\u5728 DEMO \u6a21\u5f0f\u4e0b\u8fd0\u884c\n";
        return 1;
    }

    if (secret.empty()) {
        std::cerr << "\u9519\u8bef: \u5fc5\u987b\u63d0\u4f9b secret \u53c2\u6570\n";
        std::cerr << "Usage: h_side_init <secret>\n";
        return 1;
    }

    try {
        HSideInitializer initializer(secret);
        initializer.initialize();
    } catch (const std::exception& e) {
        std::cerr << "\u521d\u59cb\u5316\u9519\u8bef: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
