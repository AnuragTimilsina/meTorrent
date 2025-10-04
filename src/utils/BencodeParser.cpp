#include "BencodeParser.hpp"
#include <stdexcept>
#include <algorithm>

json BencodeParser::decode_bencoded_value(const std::string& s, size_t& pos) {
    if (pos >= s.size()) {
        throw std::runtime_error("Unexpected end of bencoded string");
    }

    char c = s[pos];

    if (std::isdigit(c)) {
        size_t colon = s.find(':', pos);
        if (colon == std::string::npos) {
            throw std::runtime_error("Invalid bencode string length (missing ':')");
        }
        int len = std::stoi(s.substr(pos, colon - pos));
        pos = colon + 1;
        if (pos + len > s.size()) {
            throw std::runtime_error("Invalid bencode string (length exceeds input)");
        }
        std::string str = s.substr(pos, len);
        pos += len;
        return json(str);

    } else if (c == 'i') {
        pos++;
        size_t ePos = s.find('e', pos);
        if (ePos == std::string::npos) {
            throw std::runtime_error("Invalid bencode integer (missing 'e')");
        }
        long long value = std::stoll(s.substr(pos, ePos - pos));
        pos = ePos + 1;
        return json(value);

    } else if (c == 'l') {
        pos++;
        json arr = json::array();
        while (pos < s.size() && s[pos] != 'e') {
            arr.push_back(decode_bencoded_value(s, pos));
        }
        if (pos >= s.size()) {
            throw std::runtime_error("Unterminated bencode list");
        }
        pos++; // skip 'e'
        return arr;

    } else if (c == 'd') {
        pos++;
        json obj = json::object();
        while (pos < s.size() && s[pos] != 'e') {
            json key = decode_bencoded_value(s, pos);
            if (!key.is_string()) {
                throw std::runtime_error("Bencode dictionary key is not a string");
            }
            json value = decode_bencoded_value(s, pos);
            obj[key.get<std::string>()] = value;
        }
        if (pos >= s.size()) {
            throw std::runtime_error("Unterminated bencode dictionary");
        }
        pos++; // skip 'e'
        return obj;

    } else {
        throw std::runtime_error("Unhandled encoded value at pos " +
                                 std::to_string(pos) +
                                 " (char='" + std::string(1, c) + "')");
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
