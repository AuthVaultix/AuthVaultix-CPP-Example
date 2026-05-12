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

    class VaultixApp {
    public:
        VaultixApp(std::string name, std::string ownerid, std::string secret, std::string version);

        bool connect();
        bool authenticate(std::string username, std::string password);
        bool create_account(std::string username, std::string password, std::string key, std::string email = "");
        bool activate_license(std::string key);
        bool validate_session();
        bool upgrade_account(std::string username, std::string key);

        bool send_log(std::string message);
        bool apply_ban(std::string reason);
        void terminate_session();
        void update_username(std::string new_username);

        std::string fetch_user_data(std::string varid);
        bool update_user_data(std::string varid, std::string value);
        std::string fetch_global_data(std::string varid);

        bool download_payload(std::string fileid, std::vector<unsigned char>& output);

        bool send_chat_message(std::string message, std::string channel);
        std::vector<ChatMessage> fetch_chat_messages(std::string channel);

        std::vector<OnlineUser> get_online_users();

        bool verify_hardware_status();
        bool reset_password(std::string username, std::string email);

        // Properties
        UserInfo active_profile;
        std::string server_feedback;
        bool is_connected = false;

    private:
        std::string app_name;
        std::string owner_id;
        std::string secret;
        std::string version;
        std::string session_id;
        std::string enc_key;
        std::string api_url = "https://authvaultix.com/api/1.0/";

        std::string dispatch_payload(std::string type, std::vector<std::pair<std::string, std::string>> params);
        std::string compute_mac(std::string key, std::string data);
        std::string obtain_hardware_id();
        std::string compute_file_checksum();
        std::string create_entropy_iv();
        bool verify_signature(std::string body, std::string signature, std::string type);

        void parse_profile_data(const json& info);
        void verify_server_ack(const json& j);
        void halt_execution(std::string msg);
    };
}
