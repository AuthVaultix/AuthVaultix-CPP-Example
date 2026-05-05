#include "AuthVaultix.hpp"
#include "skCrypt.h"
#include <iostream>
#include <thread>
#include <chrono>
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Crypt32.lib")
using namespace AuthVaultix;

int main() {
    // Application Credentials (Hardened with skCrypt)
    auto name = skCrypt("c_pluss");
    auto ownerid = skCrypt("5d36476ca4");
    auto secret = skCrypt("4d5f30bb36e49ef838f7f65f27cc97d34a4e02ad4b960c2e54881db3d5ed7a99");
    auto version = skCrypt("1.0");

    AuthVaultixClient client(name.decrypt(), ownerid.decrypt(), secret.decrypt(), version.decrypt());

    std::cout << "[+] Initializing SDK...\n\n";

    if (!client.init()) {
        std::cout << "[-] Initialization Error: " << client.response_message << std::endl;
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
        success = client.login(user, pass);
    }
    else if (opt == 2) {
        std::string user, pass, key;
        std::cout << "Username: "; std::cin >> user;
        std::cout << "Password: "; std::cin >> pass;
        std::cout << "License Key: "; std::cin >> key;
        success = client.register_user(user, pass, key);
    }
    else if (opt == 3) {
        std::string key;
        std::cout << "License Key: "; std::cin >> key;
        success = client.license_login(key);
    }
    else if (opt == 4) {
        std::string user, key;
        std::cout << "Username: "; std::cin >> user;
        std::cout << "License Key: "; std::cin >> key;
        success = client.upgrade(user, key);
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
        success = client.forgot_password(user, email);
        if (success) {
            std::cout << "[+] Reset Request Sent! Check your email." << std::endl;
        } else {
            std::cout << "[-] Error: " << client.response_message << std::endl;
        }
        std::system("pause");
        return 0;
    }

    if (!success) {
        std::cout << "[-] Authentication Failed: " << client.response_message << std::endl;
        std::system("pause");
        return 1;
    }

    if (!client.user_data.subscriptions.empty()) {
        auto& sub = client.user_data.subscriptions[0];

        long long tl = sub.timeleft;
        long long days = tl / 86400;
        long long hours = (tl % 86400) / 3600;
        long long mins = (tl % 3600) / 60;

        std::cout
            << "Username: " << client.user_data.username
            << " \n\n Subscription: " << sub.name
            << " \n IP: " << client.user_data.ip
            << " \n HWID: " << client.user_data.hwid
            << " \n Expiry: " << sub.expiry
            << " \n Created: " << client.user_data.createdate
            << " \n Last Login: " << client.user_data.lastlogin
            << " \n Time Left: " << days << "d " << hours << "h " << mins << "m";
    }

    std::cout << "\n\nApplication running... (press any key to logout)" << std::endl;
    std::system("pause");

    client.logout();
    return 0;
}
