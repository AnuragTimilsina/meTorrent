#include "CryptoUtils.hpp"
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>

std::string CryptoUtils::sha1_to_hex(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

std::string CryptoUtils::hex_to_raw(const std::string& hex_string) {
    if (hex_string.size() % 2 != 0) {
        throw std::invalid_argument("Invalid hex string length");
    }
    std::string raw;
    raw.reserve(hex_string.size() / 2);

    for (size_t i = 0; i < hex_string.size(); i += 2) {
        std::string byteString = hex_string.substr(i, 2);
        char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
        raw.push_back(byte);
    }
    return raw;
}
