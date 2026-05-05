#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

using json = nlohmann::json;

namespace AuthVaultix {

    struct Subscription {
        std::string name;
        std::string key;
        std::string expiry;
        long long timeleft;
    };

    struct UserInfo {
        std::string username;
        std::string ip;
        std::string hwid;
        std::string createdate;
        std::string lastlogin;
        std::vector<Subscription> subscriptions;
    };

    struct ChatMessage {
        std::string author;
        std::string role;
        std::string message;
        long long timestamp;
    };

    struct OnlineUser {
        std::string credential;
    };

    class AuthVaultixClient {
    public:
        AuthVaultixClient(std::string name, std::string ownerid, std::string secret, std::string version);

        bool init();
        bool login(std::string username, std::string password);
        bool register_user(std::string username, std::string password, std::string key, std::string email = "");
        bool license_login(std::string key);
        bool check();
        bool upgrade(std::string username, std::string key);

        bool log(std::string message);
        bool ban(std::string reason);
        void logout();

        std::string get_var(std::string varid);
        bool set_var(std::string varid, std::string value);
        std::string get_global_var(std::string varid);

        bool download_file(std::string fileid, std::vector<unsigned char>& output);

        bool chat_send(std::string message, std::string channel);
        std::vector<ChatMessage> chat_fetch(std::string channel);

        std::vector<OnlineUser> fetch_online();

        bool check_blacklist();
        bool forgot_password(std::string username, std::string email);

        // Properties
        UserInfo user_data;
        std::string response_message;
        bool is_initialized = false;

    private:
        std::string app_name;
        std::string owner_id;
        std::string secret;
        std::string version;
        std::string session_id;
        std::string enc_key;
        std::string api_url = "https://authvaultix.com/api/1.0/";

        std::string request(std::string type, std::vector<std::pair<std::string, std::string>> params);
        std::string hash_hmac(std::string key, std::string data);
        std::string get_hwid();
        std::string get_file_hash();
        std::string generate_iv();
        bool verify_signature(std::string body, std::string signature, std::string type);

        void check_session(const json& j);
        void error(std::string msg);
    };
}
