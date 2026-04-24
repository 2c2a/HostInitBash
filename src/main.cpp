#include "h_side_init.h"

#include <iostream>
#include <string>
#include <cstdlib>

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    std::string secret;
    bool dry_run = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--dry-run") {
            dry_run = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: h_side_init <secret> [--dry-run]\n";
            std::cout << "  secret    \u4eceC\u7aef\u83b7\u53d6\u7684\u52a0\u5bc6secret\u5b57\u7b26\u4e32\n";
            std::cout << "  --dry-run \u4ec5\u663e\u793a\u5c06\u8981\u6267\u884c\u7684\u64cd\u4f5c\uff0c\u4e0d\u5b9e\u9645\u6267\u884c\n";
            return 0;
        } else if (arg[0] != '-') {
            secret = arg;
        }
    }

    const char* demo_env = std::getenv("ZASCA_DEMO");
    if (demo_env && std::string(demo_env) == "1") {
        std::cerr << "\u9519\u8bef: \u6b64\u811a\u672c\u4e0d\u80fd\u5728DEMO\u6a21\u5f0f\u4e0b\u8fd0\u884c\n";
        return 1;
    }

    if (secret.empty()) {
        std::cerr << "\u9519\u8bef: \u5fc5\u987b\u63d0\u4f9bsecret\u53c2\u6570\n";
        std::cerr << "Usage: h_side_init <secret> [--dry-run]\n";
        return 1;
    }

    try {
        HSideInitializer initializer(secret);

        if (dry_run) {
            std::cout << "Dry run\u6a21\u5f0f: \u5c06\u663e\u793a\u64cd\u4f5c\u6b65\u9aa4\u4f46\u4e0d\u4f1a\u5b9e\u9645\u6267\u884c\n";
            initializer.print_info();
            return 0;
        }

        initializer.initialize();
    } catch (const std::exception& e) {
        std::cerr << "\u521d\u59cb\u5316\u8fc7\u7a0b\u4e2d\u53d1\u751f\u9519\u8bef: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
