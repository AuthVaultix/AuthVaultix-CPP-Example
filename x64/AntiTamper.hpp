#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>

namespace AuthVaultix {

    class AntiTamper {
    public:
        enum class TamperType {
            Debugger,
            DllInjection,
            HookDetected,
            IntegrityViolation,
            MemoryModification,
            SuspiciousTool,
            Unknown
        };

        using TamperCallback = std::function<void(TamperType, const std::string&)>;

        AntiTamper();
        ~AntiTamper();

        bool initialize(const std::string& exe_path);

        bool check_debugger_present();
        bool check_suspicious_tools();
        bool check_dll_injection();
        bool check_hooks();
        bool check_integrity();

        bool run_all_checks();


        void start_monitoring(TamperCallback callback, int interval_ms = 5000);
        void stop_monitoring();

        std::string get_last_detail() const { return last_detail_; }

    private:
        std::string exe_path_;
        std::string last_detail_;
        std::vector<std::string> baseline_modules_;
        
        std::thread monitor_thread_;
        std::atomic<bool> monitoring_active_{ false };
        TamperCallback tamper_callback_;

        void monitor_loop(int interval_ms);
        std::vector<std::string> get_loaded_modules();
        bool is_known_module(const std::string& module_name);
    };
}
