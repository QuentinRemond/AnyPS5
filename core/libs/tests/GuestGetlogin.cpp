#include "prx/libc/include/general/VabiMacros.hpp"
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <lmcons.h>
#else
#include <pwd.h>
#include <unistd.h>
#endif

extern "C" int APS5_VABI getlogin_r_nid_postfix(char*, int);
extern "C" int APS5_VABI _getlogin_r_nid_postfix(char*, int);
extern "C" char* APS5_VABI getlogin_nid_postfix(void);
extern "C" char* APS5_VABI _getlogin_nid_postfix(void);
extern "C" int APS5_VABI setlogin_nid_postfix(const char*);
extern "C" int APS5_VABI _setlogin_nid_postfix(const char*);
extern "C" int* APS5_VABI __error_nid_postfix();

static void Check(bool condition, int line) {
    if (!condition) {
        std::fprintf(stderr, "getlogin check failed at line %d\n", line);
        std::abort();
    }
}
#define Require(value) Check((value), __LINE__)

static std::string HostLogin() {
#ifdef _WIN32
    wchar_t name[UNLEN + 1];
    DWORD count = UNLEN + 1;
    Require(GetUserNameW(name, &count) != 0);
    std::array<char, UNLEN * 4 + 1> output{};
    Require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1,
        output.data(), static_cast<int>(output.size()), nullptr, nullptr) > 0);
    return output.data();
#else
    const passwd* account = ::getpwuid(::geteuid());
    Require(account != nullptr && account->pw_name != nullptr && account->pw_name[0] != '\0');
    return account->pw_name;
#endif
}

static void RequireLogin(const std::string& expected) {
    std::vector<char> output(expected.size() + 3, '\x5A');
    *__error_nid_postfix() = 12345;
    Require(getlogin_r_nid_postfix(output.data() + 1, static_cast<int>(expected.size() + 1)) == 0);
    Require(*__error_nid_postfix() == 12345);
    Require(output.front() == '\x5A' && output.back() == '\x5A');
    Require(std::memcmp(output.data() + 1, expected.c_str(), expected.size() + 1) == 0);
    output.assign(output.size(), '\x5A');
    const auto saved = output;
    Require(getlogin_r_nid_postfix(output.data() + 1, static_cast<int>(expected.size())) == 34);
    Require(*__error_nid_postfix() == 12345 && output == saved);
    Require(_getlogin_r_nid_postfix(output.data() + 1, static_cast<int>(expected.size() + 1)) == 0);
    Require(std::memcmp(output.data() + 1, expected.c_str(), expected.size() + 1) == 0);
}

int main() {
    std::array<char, 4096> output;
    output.fill('\x5A');
    const auto untouched = output;
    for (int size : {0, -1, std::numeric_limits<int>::min()}) {
        *__error_nid_postfix() = 12345;
        Require(getlogin_r_nid_postfix(output.data(), size) == 34);
        Require(*__error_nid_postfix() == 12345 && output == untouched);
        Require(_getlogin_r_nid_postfix(output.data(), size) == 34);
    }
    Require(getlogin_r_nid_postfix(nullptr, 1) == 14);
    Require(_getlogin_r_nid_postfix(nullptr, 1) == 14);
    Require(*__error_nid_postfix() == 12345);
    const std::string expected = HostLogin();
    *__error_nid_postfix() = 12345;
    Require(getlogin_r_nid_postfix(output.data(), static_cast<int>(output.size())) == 0);
    Require(*__error_nid_postfix() == 12345);
    Require(std::strcmp(output.data(), expected.c_str()) == 0);
    char* login = getlogin_nid_postfix();
    Require(login != nullptr && std::strcmp(login, expected.c_str()) == 0);
    Require(*__error_nid_postfix() == 12345);
    char* loginAlias = _getlogin_nid_postfix();
    Require(loginAlias != nullptr && std::strcmp(loginAlias, expected.c_str()) == 0);
    Require(*__error_nid_postfix() == 12345);
    RequireLogin(expected);
    Require(setlogin_nid_postfix(nullptr) == -1 && *__error_nid_postfix() == 14);
    Require(_setlogin_nid_postfix(nullptr) == -1 && *__error_nid_postfix() == 14);
    std::string tooLong(33, 'a');
    Require(setlogin_nid_postfix(tooLong.c_str()) == -1 && *__error_nid_postfix() == 22);
    Require(_setlogin_nid_postfix(tooLong.c_str()) == -1 && *__error_nid_postfix() == 22);
    const char custom[] = "guestuser";
    Require(setlogin_nid_postfix(custom) == 0);
    Require(std::strcmp(getlogin_nid_postfix(), custom) == 0);
    Require(std::strcmp(_getlogin_nid_postfix(), custom) == 0);
    Require(getlogin_r_nid_postfix(output.data(), static_cast<int>(output.size())) == 0);
    Require(std::strcmp(output.data(), custom) == 0);
    Require(_getlogin_r_nid_postfix(output.data(), static_cast<int>(output.size())) == 0);
    Require(std::strcmp(output.data(), custom) == 0);
    Require(getlogin_r_nid_postfix(output.data(), static_cast<int>(std::strlen(custom))) == 34);
    Require(_getlogin_r_nid_postfix(output.data(), static_cast<int>(std::strlen(custom))) == 34);
    const char another[] = "ps5";
    Require(_setlogin_nid_postfix(another) == 0);
    Require(std::strcmp(getlogin_nid_postfix(), another) == 0);
    Require(std::strcmp(_getlogin_nid_postfix(), another) == 0);
    std::array<std::thread, 4> readers;
    for (auto& reader : readers) reader = std::thread([&] {
        for (int i = 0; i != 20; ++i) {
            Require(std::strcmp(getlogin_nid_postfix(), another) == 0);
            Require(std::strcmp(_getlogin_nid_postfix(), another) == 0);
        }
    });
    for (auto& reader : readers) reader.join();
}
