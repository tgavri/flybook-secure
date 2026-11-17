#include <iostream>
#include <string>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <memory>

// FIX for F01 (CWE-78) and F02 (CWE-120):
//  - No user input is ever placed into a shell command.
//  - QUERY_STRING is matched against a strict allow-list; only a fixed,
//    hardcoded process name is ever used.
//  - std::string replaces the fixed char[1024] buffer, so there is no
//    unbounded strcat and no buffer overflow.
int main() {
    std::cout << "Content-Type: text/plain\r\n\r\n";

    const char* qs = std::getenv("QUERY_STRING");
    const std::string key = qs ? qs : "";

    // Strict allow-list: the request selects WHICH service, never the command.
    std::string target;
    if      (key == "apache") target = "apache2";
    else if (key == "mysqld") target = "mysqld";
    else {
        std::cout << "invalid request\n";
        return 0;
    }

    // 'target' is a compile-time-safe constant from the allow-list above,
    // so no attacker-controlled data can reach the process lookup.
    const std::string cmd = "pgrep -a " + target;

    std::array<char, 256> buf{};
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        std::cout << "error\n";
        return 0;
    }
    if (std::fgets(buf.data(), buf.size(), pipe.get()) != nullptr) {
        std::cout << buf.data();
    } else {
        std::cout << target << " not running\n";
    }
    return 0;
}
