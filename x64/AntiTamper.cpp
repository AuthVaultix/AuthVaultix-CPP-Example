#include "AntiTamper.hpp"
#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <iostream>

#pragma comment(lib, "psapi.lib")

namespace AuthVaultix {

    AntiTamper::AntiTamper() {}
    AntiTamper::~AntiTamper() { stop_monitoring(); }

    bool AntiTamper::initialize(const std::string& exe_path) {
        exe_path_ = exe_path;
        baseline_modules_ = get_loaded_modules();
        return true;
    }

    std::vector<std::string> AntiTamper::get_loaded_modules() {
        std::vector<std::string> modules;
        HMODULE hMods[1024];
        HANDLE hProcess = GetCurrentProcess();
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                    std::string name = szModName;
                    std::transform(name.begin(), name.end(), name.begin(), ::tolower);
                    modules.push_back(name);
                }
            }
        }
        return modules;
    }

    bool AntiTamper::check_debugger_present() {
        if (IsDebuggerPresent()) {
            last_detail_ = "Standard Debugger Detected";
            return true;
        }

        BOOL debugPort = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugPort);
        if (debugPort) {
            last_detail_ = "Remote Debugger Detected";
            return true;
        }

        return false;
    }

    bool AntiTamper::check_suspicious_tools() {
        const std::vector<std::string> bad_tools = {
            "cheatengine", "x64dbg", "x32dbg", "ollydbg",
            "wireshark", "fiddler", "httpdebugger", "dnspy"
        };

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);

        if (Process32First(hSnap, &pe)) {
            do {
                std::string procName = pe.szExeFile;

                std::transform(
                    procName.begin(),
                    procName.end(),
                    procName.begin(),
                    ::tolower
                );

                for (const auto& tool : bad_tools) {
                    if (procName.find(tool) != std::string::npos) {
                        last_detail_ = "Suspicious tool running: " + procName;
                        CloseHandle(hSnap);
                        return true;
                    }
                }

            } while (Process32Next(hSnap, &pe));
        }

        CloseHandle(hSnap);
        return false;
    }

    bool AntiTamper::check_dll_injection() {
        std::vector<std::string> current_modules = get_loaded_modules();

        for (const auto& mod : current_modules) {
            // Check if it's a known safe/system module first
            if (is_known_module(mod)) {
                continue;
            }

            if (!baseline_modules_.empty()) {
                bool found = false;
                for (const auto& base : baseline_modules_) {
                    if (mod == base) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    last_detail_ = "Unauthorized module injected: " + mod;
                    return true;
                }
            }
        }
        return false;
    }

    bool AntiTamper::is_known_module(const std::string& module_name) {
        static const std::vector<std::string> whitelist = {
            "kernel.appcore.dll",
            "uxtheme.dll",
            "dwmapi.dll",
            "cryptbase.dll",
            "bcryptprimitives.dll",
            "ntmarta.dll",
            "kernelbase.dll",
            "kernel32.dll",
            "ntdll.dll",
            "msvcrt.dll",
            "user32.dll",
            "gdi32.dll",
            "imm32.dll",
            "combase.dll",
            "rpcrt4.dll",
            "shcore.dll",
            "advapi32.dll",
            "sechost.dll",
            "ws2_32.dll",
            "crypt32.dll",
            "wldp.dll",
            "version.dll",
            "shell32.dll",
            "ole32.dll",
            "oleaut32.dll",
            "comctl32.dll",
            "setupapi.dll",
            "cfgmgr32.dll",
            "profapi.dll",
            "winhttp.dll",
            "wininet.dll",
            "userenv.dll",
            "shlwapi.dll",
            "dbghelp.dll",
            "bcrypt.dll",
            "cryptsp.dll",
            "mswsock.dll",
            "dnsapi.dll",
            "iphlpapi.dll"
        };

        std::string lower_name = module_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

        for (const auto& safe : whitelist) {
            if (lower_name == safe) {
                return true;
            }
        }

        // Also whitelist api-ms-win- core sets which are often loaded dynamically
        if (lower_name.find("api-ms-win-") == 0 || lower_name.find("ext-ms-") == 0) {
            return true;
        }

        return false;
    }

    bool AntiTamper::check_hooks() {
        // 1. Check ExitProcess in kernel32.dll
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (hKernel32) {
            void* pExitProcess = GetProcAddress(hKernel32, "ExitProcess");
            if (pExitProcess) {
                unsigned char bytes[5];
                memcpy(bytes, pExitProcess, 5);
                if (bytes[0] == 0xE9 || bytes[0] == 0xCC || bytes[0] == 0xFF || bytes[0] == 0xE8 || 
                    (bytes[0] == 0x48 && bytes[1] == 0xB8)) {
                    last_detail_ = "Hook detected on ExitProcess";
                    return true;
                }
            }
        }

        // 2. Check key WinHTTP functions in winhttp.dll
        HMODULE hWinHttp = GetModuleHandleA("winhttp.dll");
        if (hWinHttp) {
            const char* winhttp_funcs[] = {
                "WinHttpOpen",
                "WinHttpConnect",
                "WinHttpOpenRequest",
                "WinHttpSendRequest",
                "WinHttpReceiveResponse",
                "WinHttpReadData"
            };

            for (const char* func_name : winhttp_funcs) {
                void* pFunc = GetProcAddress(hWinHttp, func_name);
                if (pFunc) {
                    unsigned char bytes[5];
                    memcpy(bytes, pFunc, 5);

                    if (bytes[0] == 0xE9 || bytes[0] == 0xCC || bytes[0] == 0xE8 ||
                        (bytes[0] == 0xFF && bytes[1] == 0x25) ||
                        (bytes[0] == 0x48 && bytes[1] == 0xB8)) {
                        last_detail_ = "Hook detected on " + std::string(func_name);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    bool AntiTamper::check_integrity() {
        return false;
    }

    bool AntiTamper::run_all_checks() {
        return check_debugger_present() || check_suspicious_tools() || check_dll_injection() || check_hooks();
    }

    void AntiTamper::start_monitoring(TamperCallback callback, int interval_ms) {
        if (monitoring_active_.load()) return;

        tamper_callback_ = callback;
        monitoring_active_.store(true);
        monitor_thread_ = std::thread(&AntiTamper::monitor_loop, this, interval_ms);
        monitor_thread_.detach();
    }

    void AntiTamper::stop_monitoring() {
        monitoring_active_.store(false);
        if (monitor_thread_.joinable()) {
            monitor_thread_.join();
        }
    }

    void AntiTamper::monitor_loop(int interval_ms) {
        while (monitoring_active_.load()) {
            if (run_all_checks()) {
                if (tamper_callback_) {
                    tamper_callback_(TamperType::DllInjection, last_detail_);
                }
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        }
    }
}
