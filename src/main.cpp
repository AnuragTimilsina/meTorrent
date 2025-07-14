#include <iostream>
#include <openssl/sha.h> // for SHA1
#include <iomanip> // for std::setw and std::setfill
#include <sstream> // for std::ostringstream
#include <fstream> 
#include <filesystem>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <stdexcept>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

// Forward declaration of the recursive helper function.
json decode_bencoded_value(const std::string& s, size_t &pos);

// Forward declaration of the json object to bencode 
std::string json_to_bencode(const json& j);

// Convert raw SHA1 digest to a hex string.
std::string sha1_to_hex(const std::string& input);


// Helper function to convert SHA1 digest to a hex string.
std::string sha1_to_hex(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH]; // Defined in OpenSSL as 20. SHA-1 produces a 160-bit hash. (20 bytes)
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}


// Recursive-descent decoder that processes one bencoded element starting at pos
std::string json_to_bencode(const json& j) {
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

    } else if (j.is_null()) {
        throw std::runtime_error("Cannot bencode null values");

    } else if (j.is_boolean()) {
        throw std::runtime_error("Cannot bencode boolean values");

    } else if (j.is_number_float()) {
        throw std::runtime_error("Cannot bencode floating-point values");

    } else {
        throw std::runtime_error("Unsupported JSON type for bencoding");
    }
}


// Recursive-descent decoder that processes one bencoded element starting at pos
json decode_bencoded_value(const std::string& s, size_t &pos) {
    if (std::isdigit(s[pos])) {
        // Decode a bencoded string: <length>:<string>
        size_t colon = s.find(':', pos);
        if (colon == std::string::npos) {
            throw std::runtime_error("Invalid string encoding: " + s);
        }
        int len = std::stoi(s.substr(pos, colon - pos));
        pos = colon + 1; // Move past the colon
        std::string str = s.substr(pos, len);
        pos += len; // Move past the string characters
        return json(str);
        
    } else if (s[pos] == 'i') {
        // Decode an integer: i<digits>e
        pos++; // skip 'i'
        size_t ePos = s.find('e', pos);
        if (ePos == std::string::npos) {
            throw std::runtime_error("Invalid integer encoding: " + s);
        }
        long long value = std::stoll(s.substr(pos, ePos - pos));
        pos = ePos + 1; // skip past 'e'
        return json(value);
        
    } else if (s[pos] == 'l') {
        // Decode a list: l<elements>e
        pos++; // skip initial 'l'
        json arr = json::array();
        while (s[pos] != 'e') {
            arr.push_back(decode_bencoded_value(s, pos)); // recursively decode each element
        }
        pos++; // skip the trailing 'e'
        return arr;
      
    } else if (s[pos] == 'd') {
        // Decode a dictionary: d<key1><value1><key2><value2>...e
        pos++; // skip initial 'd'
        json obj = json::object();
        while (s[pos] != 'e') {
            // Decode key
            json key = decode_bencoded_value(s, pos);
            if (!key.is_string()) { 
                throw std::runtime_error("Dictionary keys must be strings: " + s);
            }
            // Decode value
            json value = decode_bencoded_value(s, pos);
            obj[key.get<std::string>()] = value; // Add to the object
        }
        pos++; // skip the trailing 'e'
        return obj;
    
    } else {
        throw std::runtime_error("Unhandled encoded value: " + s);
    }
}


// Wrapper function: starts decoding at the beginning of the string.
json decode_bencoded_value(const std::string& s) {
    size_t pos = 0;
    return decode_bencoded_value(s, pos);
}


int main(int argc, char* argv[]) {
    // Flush output immediately

    // In some environments (like automated testers), 
    // you don’t want output to be buffered. 
    // You want to see logs right away.
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;


    // Shows usage help if no arguments are provided by the user in command line.
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode") {
        // "decode" needs another argument: the bencoded value to decode. 
        // If not provided, show usage help.
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }

        std::cerr << "Logs from your program will appear here!" << std::endl;

        // Actual decoding here. 
        std::string encoded_value = argv[2];
        json decoded_value = decode_bencoded_value(encoded_value);
        std::cout << decoded_value.dump() << std::endl;

    } else if (command == "info") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " info <file.torrent>" << std::endl;
            return 1;
        }

        std::string file_name = argv[2];
        std::ifstream file(file_name, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open file: " << file_name << std::endl;
            return 1;
        }

        std::filesystem::path file_path(file_name);
        std::string buffer(std::filesystem::file_size(file_path), '_');
        file.read(buffer.data(), buffer.size());

        json torrent = decode_bencoded_value(buffer);
        json info_dict = torrent["info"];

        std::string bencoded_info = json_to_bencode(info_dict);
        std::string info_hash = sha1_to_hex(bencoded_info);

        std::cout << "Tracker URL: " << torrent["announce"].get<std::string>() << std::endl;
        std::cout << "Length: " << info_dict["length"] << std::endl;
        std::cout << "Info Hash: " << info_hash << std::endl;
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}