#pragma once
#include <string>

class NetworkUtils {
public:
    static std::string url_encode(const std::string& value);
    static std::string url_decode(const std::string& encoded);
};