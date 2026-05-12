#include "AuthVaultix.hpp"
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <wincrypt.h>
#include <Lmcons.h>
#include <ctime>

namespace AuthVaultix {

    // Helper for time formatting
    std::string format_date(std::string unix_timestamp) {
        if (unix_timestamp.empty() || unix_timestamp == "0") return "N/A";
        try {
            time_t raw_time = std::stoll(unix_timestamp);
            struct tm time_info;
            localtime_s(&time_info, &raw_time);
            std::stringstream ss;
            ss << std::put_time(&time_info, "%d/%m/%Y %I:%M:%S %p");
            return ss.str();
        }
        catch (...) { return unix_timestamp; }
    }

    void VaultixApp::verify_server_ack(const json& j) {
        if (!j["success"].get<bool>()) {
            halt_execution(j["message"].get<std::string>());
        }
    }

    VaultixApp::VaultixApp(std::string name, std::string ownerid, std::string secret, std::string version)
        : app_name(name), owner_id(ownerid), secret(secret), version(version) {
    }

    bool VaultixApp::connect() {
        if (is_connected) return true;

        std::string iv = create_entropy_iv();
        enc_key = iv + "-" + secret;

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "init"},
            {"name", app_name},
            {"ownerid", owner_id},
            {"ver", version},
            {"enckey", iv},
            {"hash", compute_file_checksum()}
        };

        std::string response = dispatch_payload("init", params);
        if (response.empty()) return false;

        try {
            auto j = json::parse(response);
            verify_server_ack(j);
            if (j["success"]) {
                session_id = j["sessionid"];
                is_connected = true;
                return true;
            }
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return false;
    }

    void VaultixApp::parse_profile_data(const json& info) {
        if (info.is_null()) return;

        active_profile.username = info.value("username", "");
        active_profile.ip = info.value("ip", "");
        active_profile.hwid = info.value("hwid", "");
        active_profile.createdate = format_date(info.value("createdate", ""));
        active_profile.lastlogin = format_date(info.value("lastlogin", ""));

        active_profile.subscriptions.clear();
        if (info.contains("subscriptions") && info["subscriptions"].is_array()) {
            for (auto& sub : info["subscriptions"]) {
                Subscription s;
                s.name = sub.value("subscription", "");
                s.key = sub.value("key", "");
                s.expiry = format_date(sub.value("expiry", ""));
                s.timeleft = sub.value("timeleft", 0LL);
                active_profile.subscriptions.push_back(s);
            }
        }
    }

    bool VaultixApp::authenticate(std::string username, std::string password) {
        if (!is_connected) { halt_execution("Not initialized"); return false; }

        auto iv = create_entropy_iv();
        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "login"},
            {"username", username},
            {"pass", password},
            {"hwid", obtain_hardware_id()},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("login", params);
        try {
            auto j = json::parse(response);
            
            if (j.contains("message"))
                server_feedback = j["message"].get<std::string>();

            // Check for success (supports both boolean and string "true")
            bool success = false;
            if (j.contains("success")) {
                if (j["success"].is_boolean()) success = j["success"].get<bool>();
                else if (j["success"].is_string()) success = (j["success"].get<std::string>() == "true");
            }

            if (success) {
                if (j.contains("sessionid")) session_id = j["sessionid"].get<std::string>();
                
                if (j.contains("info")) {
                    parse_profile_data(j["info"]);
                }
                return true;
            }
        }
        catch (const std::exception& ex) {
            std::cout << "[SDK ERROR] " << ex.what() << std::endl;
        }
        return false;
    }

    bool VaultixApp::create_account(std::string username, std::string password, std::string key, std::string email) {
        if (!is_connected) { halt_execution("Not initialized"); return false; }

        auto iv = create_entropy_iv();
        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "register"},
            {"username", username},
            {"pass", password},
            {"key", key},
            {"email", email},
            {"hwid", obtain_hardware_id()},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("register", params);
        try {
            auto j = json::parse(response);
            if (j.contains("message"))
                server_feedback = j["message"].get<std::string>();
            
            bool success = false;
            if (j.contains("success")) {
                if (j["success"].is_boolean()) success = j["success"].get<bool>();
                else if (j["success"].is_string()) success = (j["success"].get<std::string>() == "true");
            }

            if (success) {
                if (j.contains("sessionid")) session_id = j["sessionid"].get<std::string>();
                if (j.contains("info")) {
                    parse_profile_data(j["info"]);
                }
                return true;
            }
        }
        catch (...) {}
        return false;
    }

    bool VaultixApp::activate_license(std::string key) {
        if (!is_connected) { halt_execution("Not initialized"); return false; }

        auto iv = create_entropy_iv();
        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "license"},
            {"key", key},
            {"hwid", obtain_hardware_id()},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("license", params);
        try {
            auto j = json::parse(response);
            if (j.contains("message"))
                server_feedback = j["message"].get<std::string>();

            bool success = false;
            if (j.contains("success")) {
                if (j["success"].is_boolean()) success = j["success"].get<bool>();
                else if (j["success"].is_string()) success = (j["success"].get<std::string>() == "true");
            }

            if (success) {
                if (j.contains("sessionid")) session_id = j["sessionid"].get<std::string>();
                if (j.contains("info")) {
                    parse_profile_data(j["info"]);
                }
                return true;
            }
        }
        catch (...) {}
        return false;
    }

    bool VaultixApp::validate_session() {
        if (!is_connected) { halt_execution("Not initialized"); return false; }

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "check"},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("check", params);
        try {
            auto j = json::parse(response);
            server_feedback = j["message"];
            verify_server_ack(j);
            return j["success"];
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return false;
    }

    bool VaultixApp::upgrade_account(std::string username, std::string key) {
        if (!is_connected) { halt_execution("Not initialized"); return false; }

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "upgrade"},
            {"username", username},
            {"key", key},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("upgrade", params);
        try {
            auto j = json::parse(response);
            if (j.contains("message"))
                server_feedback = j["message"].get<std::string>();

            bool success = false;
            if (j.contains("success")) {
                if (j["success"].is_boolean()) success = j["success"].get<bool>();
                else if (j["success"].is_string()) success = (j["success"].get<std::string>() == "true");
            }
            return success;
        }
        catch (...) {}
        return false;
    }

    bool VaultixApp::reset_password(std::string username, std::string email) {
        if (!is_connected) { halt_execution("Not initialized"); return false; }

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "forgot"},
            {"username", username},
            {"email", email},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("forgot", params);
        try {
            auto j = json::parse(response);
            if (j.contains("message"))
                server_feedback = j["message"].get<std::string>();

            bool success = false;
            if (j.contains("success")) {
                if (j["success"].is_boolean()) success = j["success"].get<bool>();
                else if (j["success"].is_string()) success = (j["success"].get<std::string>() == "true");
            }
            return success;
        }
        catch (...) {}
        return false;
    }

    void VaultixApp::terminate_session() {
        if (!is_connected || session_id.empty()) return;

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "logout"},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        dispatch_payload("logout", params);
        session_id = "";
        is_connected = false;
    }

    std::string VaultixApp::fetch_user_data(std::string varid) {
        if (!is_connected) return "";

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "var"},
            {"varid", varid},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("var", params);
        try {
            auto j = json::parse(response);
            server_feedback = j["message"];
            verify_server_ack(j);
            if (j["success"]) return j["response"];
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return "";
    }

    bool VaultixApp::update_user_data(std::string varid, std::string data) {
        if (!is_connected) return false;

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "setvar"},
            {"varid", varid},
            {"data", data},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("setvar", params);
        try {
            auto j = json::parse(response);
            server_feedback = j["message"];
            verify_server_ack(j);
            return j["success"];
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return false;
    }

    std::string VaultixApp::fetch_global_data(std::string varid) {
        if (!is_connected) return "";

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "getvar"},
            {"varid", varid},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("getvar", params);
        try {
            auto j = json::parse(response);
            server_feedback = j["message"];
            verify_server_ack(j);
            if (j["success"]) return j["message"];
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return "";
    }

    bool VaultixApp::send_log(std::string msg) {
        if (!is_connected) return false;

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "log"},
            {"pcname", ""},
            {"message", msg},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("log", params);
        return true;
    }

    bool VaultixApp::download_payload(std::string fileid, std::vector<unsigned char>& output) {
        if (!is_connected) return false;

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "file"},
            {"fileid", fileid},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("file", params);
        try {
            auto j = json::parse(response);
            if (j["success"]) {
                std::string b64 = j["contents"];
                DWORD dwLen = 0;
                CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, NULL, &dwLen, NULL, NULL);
                output.resize(dwLen);
                CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, output.data(), &dwLen, NULL, NULL);
                return true;
            }
            verify_server_ack(j);
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return false;
    }

    bool VaultixApp::send_chat_message(std::string msg, std::string channel) {
        if (!is_connected) return false;

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "chatsend"},
            {"message", msg},
            {"channel", channel},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("chatsend", params);
        try {
            auto j = json::parse(response);
            server_feedback = j["message"];
            verify_server_ack(j);
            return j["success"];
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return false;
    }

    std::vector<ChatMessage> VaultixApp::fetch_chat_messages(std::string channel) {
        std::vector<ChatMessage> messages;
        if (!is_connected) return messages;

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "chatget"},
            {"channel", channel},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("chatget", params);
        try {
            auto j = json::parse(response);
            verify_server_ack(j);
            if (j["success"] && j.contains("messages") && j["messages"].is_array()) {
                for (auto& m : j["messages"]) {
                    messages.push_back({ m["author"], m["message"], format_date(m["timestamp"]) });
                }
            }
            server_feedback = j["message"];
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return messages;
    }

    bool VaultixApp::verify_hardware_status() {
        if (!is_connected) return false;

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "checkblacklist"},
            {"hwid", obtain_hardware_id()},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("checkblacklist", params);
        try {
            auto j = json::parse(response);
            verify_server_ack(j);
            return j["success"];
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return false;
    }

    bool VaultixApp::apply_ban(std::string reason) {
        if (!is_connected) return false;

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "ban"},
            {"reason", reason},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("ban", params);
        try {
            auto j = json::parse(response);
            if (j.contains("message"))
                server_feedback = j["message"].get<std::string>();
            verify_server_ack(j);
            
            bool success = false;
            if (j.contains("success")) {
                if (j["success"].is_boolean()) success = j["success"].get<bool>();
                else if (j["success"].is_string()) success = (j["success"].get<std::string>() == "true");
            }
            return success;
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return false;
    }

    void VaultixApp::update_username(std::string new_username) {
        if (!is_connected) { halt_execution("Not initialized"); return; }

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "changeusername"},
            {"newUsername", new_username},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("changeusername", params);
        try {
            auto j = json::parse(response);
            if (j.contains("message"))
                server_feedback = j["message"].get<std::string>();
            verify_server_ack(j);

            bool success = false;
            if (j.contains("success")) {
                if (j["success"].is_boolean()) success = j["success"].get<bool>();
                else if (j["success"].is_string()) success = (j["success"].get<std::string>() == "true");
            }

            if (success) {
                session_id = "";
                is_connected = false;
            }
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
    }

    std::vector<OnlineUser> VaultixApp::get_online_users() {
        std::vector<OnlineUser> users;
        if (!is_connected) return users;

        std::vector<std::pair<std::string, std::string>> params = {
            {"type", "fetchonline"},
            {"sessionid", session_id},
            {"name", app_name},
            {"ownerid", owner_id}
        };

        std::string response = dispatch_payload("fetchonline", params);
        try {
            auto j = json::parse(response);
            verify_server_ack(j);
            if (j.contains("users") && j["users"].is_array()) {
                for (auto& u : j["users"]) {
                    users.push_back({ u.value("credential", "") });
                }
            }
            if (j.contains("message")) server_feedback = j["message"].get<std::string>();
        }
        catch (...) { halt_execution("Integrity Check Failed"); }
        return users;
    }

    std::string VaultixApp::dispatch_payload(std::string type, std::vector<std::pair<std::string, std::string>> params) {
        HINTERNET hSession = WinHttpOpen(L"AuthVaultix/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return "";

        HINTERNET hConnect = WinHttpConnect(hSession, L"authvaultix.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/v1/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

        std::string body;
        for (size_t i = 0; i < params.size(); ++i) {
            body += params[i].first + "=" + params[i].second + (i == params.size() - 1 ? "" : "&");
        }

        std::string signature = compute_mac(enc_key, body);
        std::wstring headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
        headers += L"X-Signature: " + std::wstring(signature.begin(), signature.end()) + L"\r\n";

        bool sent = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0);

        std::string result;
        if (sent && WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD dwSize = 0;
            do {
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                if (dwSize == 0) break;
                std::vector<char> buffer(dwSize);
                DWORD dwRead = 0;
                if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwRead)) {
                    result.append(buffer.data(), dwRead);
                }
            } while (dwSize > 0);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return result;
    }

    std::string VaultixApp::compute_mac(std::string key, std::string body) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);

        DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);

        std::vector<BYTE> hashObject(cbHashObject);
        std::vector<BYTE> hash(cbHash);

        BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, (PBYTE)key.c_str(), (ULONG)key.length(), 0);
        BCryptHashData(hHash, (PBYTE)body.c_str(), (ULONG)body.length(), 0);
        BCryptFinishHash(hHash, hash.data(), cbHash, 0);

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        std::stringstream ss;
        for (BYTE b : hash) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return ss.str();
    }

#include <sddl.h>

    std::string VaultixApp::obtain_hardware_id() {
        char machine[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(machine);
        GetComputerNameA(machine, &size);

        char user[UNLEN + 1];
        size = sizeof(user);
        GetUserNameA(user, &size);

        char domain[MAX_PATH];
        size = sizeof(domain);
        GetEnvironmentVariableA("USERDOMAIN", domain, size);

        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        std::string arch = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" : "x86";

        wchar_t wCulture[LOCALE_NAME_MAX_LENGTH];
        GetUserDefaultLocaleName(wCulture, LOCALE_NAME_MAX_LENGTH);
        char culture[LOCALE_NAME_MAX_LENGTH];
        size_t converted = 0;
        wcstombs_s(&converted, culture, LOCALE_NAME_MAX_LENGTH, wCulture, _TRUNCATE);

        std::string sid_str = "S-0-0";
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DWORD dwSize = 0;
            GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
            PTOKEN_USER pUser = (PTOKEN_USER)malloc(dwSize);
            if (GetTokenInformation(hToken, TokenUser, pUser, dwSize, &dwSize)) {
                LPSTR psid = NULL;
                if (ConvertSidToStringSidA(pUser->User.Sid, &psid)) {
                    sid_str = psid;
                    LocalFree(psid);
                }
            }
            free(pUser);
            CloseHandle(hToken);
        }

        std::string raw = std::string(machine) + "|" + user + "|" + domain + "|Win10|" + arch + "|4.0.30319.42000|" + culture + "|" + sid_str;
        std::string hash = compute_mac(secret, raw);
        std::transform(hash.begin(), hash.end(), hash.begin(), ::toupper);

        std::string formatted;
        for (size_t i = 0; i < hash.length(); i++) {
            if (i > 0 && i % 4 == 0) formatted += "-";
            formatted += hash[i];
        }
        return formatted;
    }

    std::string VaultixApp::create_entropy_iv() {
        UUID uuid;
        UuidCreate(&uuid);
        RPC_CSTR szUuid;
        UuidToStringA(&uuid, &szUuid);
        std::string s((char*)szUuid);
        RpcStringFreeA(&szUuid);
        s.erase(std::remove(s.begin(), s.end(), '-'), s.end());
        return s.substr(0, 16);
    }

    std::string VaultixApp::compute_file_checksum() {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        return compute_mac(secret, path);
    }

    void VaultixApp::halt_execution(std::string msg) {
        MessageBoxA(NULL, msg.c_str(), "AuthVaultix Error", MB_ICONERROR);
        exit(0);
    }
}
