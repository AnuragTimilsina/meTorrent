#include "BencodeParser.hpp"
#include <stdexcept>
#include <algorithm>

json BencodeParser::decode_bencoded_value(const std::string& s, size_t& pos) {
    if (std::isdigit(s[pos])) {
        size_t colon = s.find(':', pos);
        int len = std::stoi(s.substr(pos, colon - pos));
        pos = colon + 1;
        std::string str = s.substr(pos, len);
        pos += len;
        return json(str);
    } else if (s[pos] == 'i') {
        pos++;
        size_t ePos = s.find('e', pos);
        long long value = std::stoll(s.substr(pos, ePos - pos));
        pos = ePos + 1;
        return json(value);
    } else if (s[pos] == 'l') {
        pos++;
        json arr = json::array();
        while (s[pos] != 'e') {
            arr.push_back(decode_bencoded_value(s, pos));
        }
        pos++;
        return arr;
    } else if (s[pos] == 'd') {
        pos++;
        json obj = json::object();
        while (s[pos] != 'e') {
            json key = decode_bencoded_value(s, pos);
            json value = decode_bencoded_value(s, pos);
            obj[key.get<std::string>()] = value;
        }
        pos++;
        return obj;
    } else {
        throw std::runtime_error("Unhandled encoded value: " + s);
    }
}

json BencodeParser::decode_bencoded_value(const std::string& s) {
    size_t pos = 0;
    return decode_bencoded_value(s, pos);
}

std::string BencodeParser::json_to_bencode(const json& j) {
    if (j.is_string()) {
        const std::string& str = j.get<std::string>();
        return std::to_string(str.size()) + ":" + str;
    } else if (j.is_number_integer()) {
        return "i" + std::to_string(j.get<long long>()) + "e";
    } else if (j.is_array()) {
        std::string result = "l";
        for (const auto& item : j) {
            result += json_to_bencode(item);
        }
        result += "e";
        return result;
    } else if (j.is_object()) {
        std::string result = "d";
        std::vector<std::string> keys;
        for (auto it = j.begin(); it != j.end(); ++it) {
            keys.push_back(it.key());
        }
        std::sort(keys.begin(), keys.end());
        for (const std::string& key : keys) {
            result += std::to_string(key.size()) + ":" + key;
            result += json_to_bencode(j.at(key));
        }
        result += "e";
        return result;
    } else {
        throw std::runtime_error("Unsupported JSON type for bencoding");
    }
}
