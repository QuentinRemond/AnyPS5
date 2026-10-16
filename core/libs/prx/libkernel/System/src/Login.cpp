#include "prx/libc/include/general/VabiMacros.hpp"
#include <array>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <string>
#include <system_error>
#ifdef _WIN32
#include <windows.h>
#include <lmcons.h>
#else
#include <pwd.h>
#include <unistd.h>
#endif

extern "C" int* APS5_VABI __error_nid_postfix();

namespace {
constexpr int GuestEfault = 14;
constexpr int GuestEinval = 22;
constexpr int GuestErange = 34;
constexpr std::size_t MaxLogName = 33;

std::mutex g_sessionLoginMutex;
std::string g_sessionLogin;
bool g_hasSessionLogin = false;

int ReadLogin(char* output, int size) {
    {
        std::lock_guard lock(g_sessionLoginMutex);
        if (g_hasSessionLogin) {
            const std::size_t length = g_sessionLogin.size() + 1;
            if (length > static_cast<std::size_t>(size)) return GuestErange;
            std::memcpy(output, g_sessionLogin.c_str(), length);
            return 0;
        }
    }
#ifdef _WIN32
    std::array<wchar_t, UNLEN + 1> name{};
    DWORD count = static_cast<DWORD>(name.size());
    if (!GetUserNameW(name.data(), &count))
        throw std::system_error(GetLastError(), std::system_category(), "getlogin_r: GetUserNameW");
    std::array<char, UNLEN * 4 + 1> utf8{};
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name.data(),
        static_cast<int>(count), utf8.data(), static_cast<int>(utf8.size()), nullptr, nullptr);
    if (length == 0)
        throw std::system_error(GetLastError(), std::system_category(), "getlogin_r: UTF-8 conversion");
    if (length > size) return GuestErange;
    std::memcpy(output, utf8.data(), static_cast<std::size_t>(length));
    return 0;
#else
    std::array<char, 16384> storage{};
    passwd entry{};
    passwd* account = nullptr;
    const int error = ::getpwuid_r(::geteuid(), &entry, storage.data(), storage.size(), &account);
    if (error != 0)
        throw std::system_error(error, std::generic_category(), "getlogin_r: getpwuid_r");
    if (account == nullptr || account->pw_name == nullptr || account->pw_name[0] == '\0')
        throw std::runtime_error("getlogin_r: host effective user has no account name");
    const std::size_t length = std::strlen(account->pw_name) + 1;
    if (length > static_cast<std::size_t>(size)) return GuestErange;
    std::memcpy(output, account->pw_name, length);
    return 0;
#endif
}
}

extern "C" {
int APS5_VABI getlogin_r_nid_postfix(char* output, int size) {
    if (size <= 0) return GuestErange;
    if (output == nullptr) return GuestEfault;
    const int saved = errno;
    const int result = ReadLogin(output, size);
    errno = saved;
    return result;
}

int APS5_VABI _getlogin_r_nid_postfix(char* output, int size) {
    return getlogin_r_nid_postfix(output, size);
}

char* APS5_VABI getlogin_nid_postfix(void) {
    thread_local std::array<char, 256> buffer{};
    const int error = getlogin_r_nid_postfix(buffer.data(), static_cast<int>(buffer.size()));
    if (error != 0) {
        *__error_nid_postfix() = error;
        return nullptr;
    }
    return buffer.data();
}

char* APS5_VABI _getlogin_nid_postfix(void) {
    return getlogin_nid_postfix();
}

int APS5_VABI setlogin_nid_postfix(const char* name) {
    if (name == nullptr) {
        *__error_nid_postfix() = GuestEfault;
        return -1;
    }
    const std::size_t length = std::strlen(name);
    if (length >= MaxLogName) {
        *__error_nid_postfix() = GuestEinval;
        return -1;
    }
    {
        std::lock_guard lock(g_sessionLoginMutex);
        g_sessionLogin.assign(name, length);
        g_hasSessionLogin = true;
    }
    return 0;
}

int APS5_VABI _setlogin_nid_postfix(const char* name) {
    return setlogin_nid_postfix(name);
}
}
