#pragma once
#include "../lib/nlohmann/json.hpp"
#include <string>

using json = nlohmann::json;

class BencodeParser {
public:
    static json decode_bencoded_value(const std::string& s);
    static json decode_bencoded_value(const std::string& s, size_t& pos);
    static std::string json_to_bencode(const json& j);
};