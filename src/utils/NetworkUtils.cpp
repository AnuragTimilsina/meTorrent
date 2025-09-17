#include "NetworkUtils.hpp"
#include <sstream>
#include <iomanip>
#include <cctype>

std::string NetworkUtils::url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (isalnum(uc) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << int(uc);
        }
    }
    return escaped.str();
}

std::string NetworkUtils::url_decode(const std::string& encoded) {
    std::string result;
    for (size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            std::string hex = encoded.substr(i + 1, 2);
            char ch = static_cast<char>(std::stoi(hex, nullptr, 16));
            result.push_back(ch);
            i += 2;
        } else if (encoded[i] == '+') {
            result.push_back(' ');
        } else {
            result.push_back(encoded[i]);
        }
    }
    return result;
}
