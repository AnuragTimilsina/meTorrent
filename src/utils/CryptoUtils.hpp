#pragma once
#include <string>

class CryptoUtils {
public:
    static std::string sha1_to_hex(const std::string& input);
    static std::string hex_to_raw(const std::string& hex_string);
};