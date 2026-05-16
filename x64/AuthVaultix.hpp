#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <nlohmann/json.hpp>
#include "AntiTamper.hpp"

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
        std::string message;
        std::string timestamp;
    };

    struct OnlineUser {
        std::string username;
    };

    class VaultixApp {
    public:
        VaultixApp(std::string name, std::string ownerid, std::string secret, std::string version);

        bool connect();
        bool authenticate(std::string username, std::string password);
        bool create_account(std::string username, std::string password, std::string key, std::string email = "");
        bool activate_license(std::string key);
        bool validate_session(bool requireAuthenticated = true);
        bool upgrade_account(std::string username, std::string key);


        bool verify_auth_integrity();

        bool send_log(std::string message);
        bool apply_ban(std::string reason);
        void terminate_session();

        // Data Management
        std::string fetch_user_data(std::string varid);
        bool update_user_data(std::string varid, std::string data);
        std::string fetch_global_data(std::string varid);
        bool download_payload(std::string fileid, std::vector<unsigned char>& output);

        // Community Features
        bool send_chat_message(std::string message, std::string channel);
        std::vector<ChatMessage> fetch_chat_messages(std::string channel);
        std::vector<OnlineUser> get_online_users();
        void update_username(std::string new_username);
        bool verify_hardware_status();
        bool reset_password(std::string username, std::string email);


        bool report_tamper(const std::string& reason);


        void start_heartbeat(int interval_seconds = 15);
        void stop_heartbeat();


        void start_protection(int heartbeat_sec = 15, int tamper_check_ms = 5000);
        void stop_protection();

        UserInfo active_profile;
        std::string server_feedback;
        AntiTamper anti_tamper;


        bool is_genuinely_authenticated() const { return auth_verified_; }

    private:

        bool auth_verified_ = false;
        std::string server_nonce_;
        std::string session_token_;
        std::string auth_proof_;

        std::string app_name;
        std::string owner_id;
        std::string secret;
        std::string version;
        std::string session_id;
        std::string enc_key;
        


        std::thread heartbeat_thread_;
        std::atomic<bool> heartbeat_running_{ false };
        void heartbeat_loop(int interval_sec);


        void on_tamper_detected(AntiTamper::TamperType type, const std::string& detail);

        std::string dispatch_payload(std::string type, std::vector<std::pair<std::string, std::string>> params);
        std::string compute_mac(std::string key, std::string data);
        std::string obtain_hardware_id();
        std::string create_entropy_iv();
        std::string compute_file_checksum();
        void parse_profile_data(const json& info);
        void verify_server_ack(const json& j);
        void halt_execution(std::string msg);

        bool is_connected = false;
    };
}
