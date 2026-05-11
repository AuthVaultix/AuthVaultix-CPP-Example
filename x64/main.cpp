#include "AuthVaultix.hpp"
#include "skCrypt.h"
#include <iostream>
#include <thread>
#include <chrono>
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Crypt32.lib")
using namespace AuthVaultix;

int main() {
    // copy and paste from https://authvaultix.com/win/app/x and replace these string variables
    // Please watch tutorial HERE https://youtu.be/0rCVaszXg5k?si=VIPmVfYYfXfQwnyg
    // Application Credentials (Hardened with skCrypt)
    auto name = skCrypt("name"); // App name
    auto ownerid = skCrypt("ownerid");// Account ID
    auto secret = skCrypt("");// Secret ID
    auto version = skCrypt("1.0");// Application version. Used for automatic downloads see video here 

    VaultixApp client(name.decrypt(), ownerid.decrypt(), secret.decrypt(), version.decrypt());


    std::cout << "[+] Initializing SDK...\n\n";

    if (!client.connect()) {
        std::cout << "[-] Initialization Error: " << client.server_feedback << std::endl;
        std::system("pause");
        return 1;
    }

    std::cout << "1. Login\n2. Register\n3. License Only\n4. Upgrade\n5. Forgot Password\nChoose option: ";
    int opt;
    std::cin >> opt;

    bool success = false;
    if (opt == 1) {
        std::string user, pass;
        std::cout << "Username: "; std::cin >> user;
        std::cout << "Password: "; std::cin >> pass;
        success = client.authenticate(user, pass);
    }
    else if (opt == 2) {
        std::string user, pass, key;
        std::cout << "Username: "; std::cin >> user;
        std::cout << "Password: "; std::cin >> pass;
        std::cout << "License Key: "; std::cin >> key;
        success = client.create_account(user, pass, key);
    }
    else if (opt == 3) {
        std::string key;
        std::cout << "License Key: "; std::cin >> key;
        success = client.activate_license(key);
    }
    else if (opt == 4) {
        std::string user, key;
        std::cout << "Username: "; std::cin >> user;
        std::cout << "License Key: "; std::cin >> key;
        success = client.upgrade_account(user, key);
        if (success) {
            std::cout << "[+] Upgrade Successful! Please restart the app." << std::endl;
            std::system("pause");
            return 0;
        }
    }
    else if (opt == 5) {
        std::string user, email;
        std::cout << "Username: "; std::cin >> user;
        std::cout << "Email: "; std::cin >> email;
        success = client.reset_password(user, email);
        if (success) {
            std::cout << "[+] Reset Request Sent! Check your email." << std::endl;
        } else {
            std::cout << "[-] Error: " << client.server_feedback << std::endl;
        }
        std::system("pause");
        return 0;
    }

    if (!success) {
        std::cout << "[-] Authentication Failed: " << client.server_feedback << std::endl;
        std::system("pause");
        return 1;
    }

    if (!client.active_profile.subscriptions.empty()) {
        auto& sub = client.active_profile.subscriptions[0];

        long long tl = sub.timeleft;
        long long days = tl / 86400;
        long long hours = (tl % 86400) / 3600;
        long long mins = (tl % 3600) / 60;

        std::cout
            << "Username: " << client.active_profile.username
            << " \n\n Subscription: " << sub.name
            << " \n IP: " << client.active_profile.ip
            << " \n HWID: " << client.active_profile.hwid
            << " \n Expiry: " << sub.expiry
            << " \n Created: " << client.active_profile.createdate
            << " \n Last Login: " << client.active_profile.lastlogin
            << " \n Time Left: " << days << "d " << hours << "h " << mins << "m";
    }

    std::cout << "\n\nApplication running... (press any key to logout)" << std::endl;
    std::system("pause");

    client.terminate_session();
    return 0;
}
