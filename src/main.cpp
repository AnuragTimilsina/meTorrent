#include <iostream>
#include <openssl/sha.h> // for SHA1
#include <iomanip>
#include <sstream>
#include <fstream> 
#include <filesystem>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <curl/curl.h>
#include <arpa/inet.h>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

// Function declarations
json decode_bencoded_value(const std::string& s, size_t &pos);
json decode_bencoded_value(const std::string& s);
std::string json_to_bencode(const json& j);

// SHA1 Hash
std::string sha1_to_hex(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

// URL encode
std::string url_encode(const std::string &value) {
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

// File read
std::string read_file(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// curl write callback (FIXED)
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total_size = size * nmemb;
    std::string *output = static_cast<std::string *>(userp);
    output->append((char *)contents, total_size);
    return total_size;
}

// parse peers
std::string parse_peers(const std::string &peers) {
    std::ostringstream oss;
    for (size_t i = 0; i + 6 <= peers.size(); i += 6) {
        uint8_t ip_bytes[4];
        uint16_t port;

        memcpy(ip_bytes, &peers[i], 4);
        memcpy(&port, &peers[i + 4], 2);

        std::string ip = std::to_string(ip_bytes[0]) + "." +
                         std::to_string(ip_bytes[1]) + "." +
                         std::to_string(ip_bytes[2]) + "." +
                         std::to_string(ip_bytes[3]);

        port = ntohs(port);
        oss << ip << ":" << port << std::endl;
    }
    return oss.str();
}

// Bencode decoder
json decode_bencoded_value(const std::string& s, size_t &pos) {
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

json decode_bencoded_value(const std::string& s) {
    size_t pos = 0;
    return decode_bencoded_value(s, pos);
}

// JSON → Bencode
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
    } else {
        throw std::runtime_error("Unsupported JSON type for bencoding");
    }
}

// MAIN
int main(int argc, char* argv[]) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <decode|info|peers> <args>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        std::string encoded_value = argv[2];
        json decoded_value = decode_bencoded_value(encoded_value);
        std::cout << decoded_value.dump() << std::endl;

    } else if (command == "info") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " info <file.torrent>" << std::endl;
            return 1;
        }

        std::string file_name = argv[2];
        std::string buffer = read_file(file_name);
        json torrent = decode_bencoded_value(buffer);
        json info_dict = torrent["info"];
        std::string bencoded_info = json_to_bencode(info_dict);
        std::string info_hash = sha1_to_hex(bencoded_info);

        std::cout << "Tracker URL: " << torrent["announce"].get<std::string>() << std::endl;
        std::cout << "Length: " << info_dict["length"] << std::endl;
        std::cout << "Info Hash: " << info_hash << std::endl;
        std::cout << "Piece Length: " << info_dict["piece length"] << std::endl;

        std::string pieces_raw = info_dict["pieces"];
        std::cout << "Piece Hashes: " << std::endl;
        for(size_t i = 0; i < pieces_raw.size(); i += 20) {
            std::string piece_hash = pieces_raw.substr(i, 20);
            std::ostringstream oss;
            for (unsigned char c: piece_hash) {
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c;
            }
            std::cout << oss.str() << std::endl;
        }

    }  else if (command == "peers") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " peers <file.torrent>" << std::endl;
            return 1;
        }

        std::string file_name = argv[2];
        std::string buffer = read_file(file_name);
        json torrent = decode_bencoded_value(buffer);
        json info_dict = torrent["info"];
        std::string bencoded_info = json_to_bencode(info_dict);

        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char *>(bencoded_info.c_str()), bencoded_info.size(), hash);
        std::string info_hash(reinterpret_cast<char *>(hash), SHA_DIGEST_LENGTH);

        std::string peer_id = "-PC0001-123456789012";
        int port = 6881;
        int left = info_dict["length"].get<int>();

        std::ostringstream url;
        url << torrent["announce"].get<std::string>()
            << "?info_hash=" << url_encode(info_hash)
            << "&peer_id=" << url_encode(peer_id)
            << "&port=" << port
            << "&uploaded=0&downloaded=0"
            << "&left=" << left
            << "&compact=1";

        CURL *curl = curl_easy_init();
        std::string response;

        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url.str().c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
                return 1;
            }
            curl_easy_cleanup(curl);
        }

        json tracker_response = decode_bencoded_value(response);

        if (!tracker_response.contains("peers") || !tracker_response["peers"].is_string()) {
            std::cerr << "Tracker response does not contain a valid 'peers' string." << std::endl;
            return 1;
        }

        std::string peers_compact = tracker_response["peers"];
        std::string peer_list = parse_peers(peers_compact);
        std::cout << peer_list << std::endl;
        
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
