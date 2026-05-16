#include "AuthVaultix.hpp"
#include "AntiTamper.hpp"
#include "skCrypt.h"
#include <iostream>
#include <thread>
#include <chrono>

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Crypt32.lib")

using namespace AuthVaultix;



int main() {
    {
        AntiTamper precheck;
        if (precheck.check_debugger_present() || precheck.check_suspicious_tools()) {
            return 0;
        }
    }

    // copy and paste from https://authvaultix.com/win/app/x and replace these string variables
    // Please watch tutorial HERE https://youtu.be/0rCVaszXg5k?si=VIPmVfYYfXfQwnyg
    // Application Credentials (Hardened with skCrypt)
    auto name = skCrypt("name"); // App name
    auto ownerid = skCrypt("ownerid");// Account ID
    auto secret = skCrypt("");// Secret ID
    auto version = skCrypt("1.0");// Application version. Used for automatic downloads see video here 

    VaultixApp client(name.decrypt(), ownerid.decrypt(), secret.decrypt(), version.decrypt());

    std::cout << skCrypt("[+] Initializing Secure SDK...\n").decrypt();

    if (!client.connect()) {
        std::cout << skCrypt("[-] Initialization Error: ").decrypt() << client.server_feedback << std::endl;
        std::system("pause");
        return 1;
    }

    {
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); 
        char exe_path[MAX_PATH];
        GetModuleFileNameA(NULL, exe_path, MAX_PATH);
        client.anti_tamper.initialize(std::string(exe_path));
    }

    if (client.anti_tamper.check_dll_injection() || client.anti_tamper.check_hooks()) {
        client.report_tamper(skCrypt("[PRE_AUTH_INJECTION] ").decrypt() + client.anti_tamper.get_last_detail());
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        return 0;
    }

    // UPDATED MENU AS PER USER REQUEST
    std::cout << skCrypt("\n1. Login\n2. Register\n3. License Only\n4. Upgrade\n5. Forgot Password\nChoose option: ").decrypt();
    int opt;
    std::cin >> opt;

    std::string user, pass, key, email;
    bool success = false;

    if (opt == 1) {
        std::cout << skCrypt("Username: ").decrypt(); std::cin >> user;
        std::cout << skCrypt("Password: ").decrypt(); std::cin >> pass;
        success = client.authenticate(user, pass);
    }
    else if (opt == 2) {
        std::cout << skCrypt("Username: ").decrypt(); std::cin >> user;
        std::cout << skCrypt("Password: ").decrypt(); std::cin >> pass;
        std::cout << skCrypt("License Key: ").decrypt(); std::cin >> key;
        success = client.create_account(user, pass, key);
    }
    else if (opt == 3) {
        std::cout << skCrypt("License Key: ").decrypt(); std::cin >> key;
        success = client.activate_license(key);
    }
    else if (opt == 4) {
        std::cout << skCrypt("Username: ").decrypt(); std::cin >> user;
        std::cout << skCrypt("License Key: ").decrypt(); std::cin >> key;
        success = client.upgrade_account(user, key);
        if (success) {
            std::cout << skCrypt("[+] Account upgraded successfully!\n").decrypt();
            std::system("pause");
            return 0;
        }
    }
    else if (opt == 5) {
        std::cout << skCrypt("Username: ").decrypt(); std::cin >> user;
        std::cout << skCrypt("Email: ").decrypt(); std::cin >> email;
        success = client.reset_password(user, email);
        if (success) {
            std::cout << skCrypt("[+] Password reset request sent! Check your email.\n").decrypt();
            std::system("pause");
            return 0;
        }
    }

    if (!success) {
        std::cout << skCrypt("\n[-] Error: ").decrypt() << client.server_feedback << std::endl;
        std::system("pause");
        return 1;
    }

    std::cout << skCrypt("[+] Verifying integrity...\n").decrypt();

    if (!client.is_genuinely_authenticated() || !client.verify_auth_integrity()) {
        client.report_tamper(skCrypt("[AUTH_INTEGRITY_FAILURE]").decrypt());
        client.apply_ban(skCrypt("AutoBan: Fake auth detected").decrypt());
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        return 0;
    }

    if (client.anti_tamper.run_all_checks()) {
        client.report_tamper(skCrypt("[POST_AUTH_TAMPER] ").decrypt() + client.anti_tamper.get_last_detail());
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        return 0;
    }

    client.start_protection(15, 5000);

    std::cout << skCrypt("[+] Access Granted. Welcome, ").decrypt() << client.active_profile.username << "!\n";

    if (!client.active_profile.subscriptions.empty()) {
        auto& sub = client.active_profile.subscriptions[0];

        std::cout << skCrypt("\n========== USER INFO ==========\n").decrypt();

        std::cout << skCrypt("    Username:     ").decrypt()
            << client.active_profile.username << "\n";

        std::cout << skCrypt("    Subscription: ").decrypt()
            << sub.name << "\n";

        std::cout << skCrypt("    Expiry:       ").decrypt()
            << sub.expiry << "\n";

        std::cout << skCrypt("    IP Address:   ").decrypt()
            << client.active_profile.ip << "\n";

        std::cout << skCrypt("    HWID:         ").decrypt()
            << client.active_profile.hwid << "\n";

        std::cout << skCrypt("    Created At:   ").decrypt()
            << client.active_profile.createdate << "\n";

        std::cout << skCrypt("    Last Login:   ").decrypt()
            << client.active_profile.lastlogin << "\n";

        std::cout << skCrypt("    Session ID:   ").decrypt()
            << client.server_feedback << "\n";

        std::cout << skCrypt("    Auth Status:  ").decrypt()
            << (client.is_genuinely_authenticated() ? skCrypt("Verified").decrypt() : skCrypt("Unverified").decrypt())
            << "\n";

        std::cout << skCrypt("================================\n").decrypt();
    }

    std::cout << skCrypt("Press any key to logout").decrypt() << std::endl;
    std::system("pause");
   
    client.stop_protection();
    client.terminate_session();
    return 0;
}
