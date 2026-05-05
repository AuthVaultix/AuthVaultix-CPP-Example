<p align="center">
  <img src="banner.png" alt="AuthVaultix Banner" width="100%">
</p>

<h1 align="center">🛡️ AuthVaultix C++ SDK</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C%2B%2B17-00599C?style=for-the-badge&logo=cplusplus" alt="C++17">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D4?style=for-the-badge&logo=windows" alt="Windows">
  <img src="https://img.shields.io/badge/Security-Hardened-blueviolet?style=for-the-badge&logo=securityscorecard" alt="Security">
  <img src="https://img.shields.io/badge/Status-Production--Ready-success?style=for-the-badge" alt="Status">
</p>

<p align="center">
  <b>AuthVaultix</b> is a high-performance, enterprise-grade C++ authentication library designed for software protection. Built from the ground up to provide a seamless, secure, and intuitive integration experience for C++ developers.
</p>

---

## 🌟 Key Features

### 🔐 Robust Authentication
- **Standard Auth**: Secure Login, Registration, and License activation.
- **Subscription Management**: Seamlessly upgrade user subscriptions with license keys.
- **Password Recovery**: Integrated "Forgot Password" functionality via email.
- **Session Integrity**: Server-side session validation to prevent memory tampering.

### 🛡️ Advanced Security
- **Compile-Time Obfuscation**: Deep integration with `skCrypt` to encrypt strings at compile-time, defeating static analysis and string dumping.
- **HWID Verification**: SID-based hardware identification that matches production standards, preventing account sharing.
- **Blacklist Protection**: Built-in checks to automatically block blacklisted users or HWIDs.
- **Ban System**: Programmatically ban malicious users directly from the client.

### 📦 Utility & Social
- **Cloud Variables**: Fetch global or user-specific variables stored securely on the server.
- **Secure File Downloads**: Download protected binaries as Base64-encoded buffers.
- **Encrypted Chat**: Fetch and send messages in specific channels with role-based visibility.
- **Online Tracking**: Monitor and fetch the list of currently active users.

---

## 🚀 Getting Started

### Prerequisites
- **Visual Studio 2019** or newer.
- **C++17 Standard** (Required for `skCrypt` and modern syntax).
- **Libraries**: `WinHTTP`, `BCrypt`, `Crypt32` (Automatically linked via `#pragma comment`).

### Installation
1. Clone the repository or download the source files.
2. Add `AuthVaultix.hpp`, `AuthVaultix.cpp`, and `skCrypt.h` to your project.
3. Install **nlohmann/json** (Available via NuGet or [GitHub](https://github.com/nlohmann/json)).

---

## 🖥️ Usage Example

```cpp
#include "AuthVaultix.hpp"
#include "skCrypt.h"
#include <iostream>

int main() {
    // 🛡️ Encrypt credentials at compile-time to hide from crackers
    auto name = skCrypt("Your_App_Name");
    auto ownerid = skCrypt("Your_Owner_ID");
    auto secret = skCrypt("Your_App_Secret");
    auto version = skCrypt("1.0");

    // Initialize the client
    AuthVaultix::AuthVaultixClient client(
        name.decrypt(), 
        ownerid.decrypt(), 
        secret.decrypt(), 
        version.decrypt()
    );

    if (!client.init()) {
        std::cout << "❌ Initialization Failed: " << client.response_message << std::endl;
        return 1;
    }

    std::cout << "✅ Connected to AuthVaultix!" << std::endl;

    // Perform Login
    if (client.login("user123", "password")) {
        std::cout << "👋 Welcome, " << client.user_data.username << "!" << std::endl;
        std::cout << "📅 Created: " << client.user_data.createdate << std::endl;
        
        // Fetch a cloud variable
        std::string update_url = client.get_global_var("UpdateURL");
        std::cout << "🌐 Server Update URL: " << update_url << std::endl;
    } else {
        std::cout << "❌ Login Failed: " << client.response_message << std::endl;
    }

    return 0;
}
```

---

## 🛠️ Security Best Practices

> [!IMPORTANT]
> To maintain maximum security for your application, follow these guidelines:

1. **Always use Release mode**: Debug builds contain symbols that make cracking significantly easier.
2. **String Protection**: Use `skCrypt()` for *every* sensitive string (API Secret, App Name, etc.).
3. **Control Flow**: Implement server-side checks and use the `client.check()` method periodically.
4. **Final Protection**: Use a commercial protector like **VMProtect** or **Themida** on your compiled `.exe` for virtualization and anti-debug layers.

---

## 📄 License
This project is licensed under the **Elastic License 2.0**. See the [LICENSE](LICENSE) file for details.

<p align="center">
  Developed with ❤️ for the Security Community.
</p>
