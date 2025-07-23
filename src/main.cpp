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

#include <random>
#include <cstring> // For memcpy
#include <netinet/in.h> // For htons, sockadder_in
#include <sys/socket.h> 
#include <unistd.h> 
#include <netdb.h>

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

// Utility: generate 20 random bytes
std::string generate_peer_id() {
    std::string peer_id = "-PC0001-"; // Prefix (you can change this)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    while (peer_id.size() < 20){
        peer_id += static_cast<char>(dis(gen));
    }
    return peer_id;
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
        
    } else if (command == "handshake"){
        if (argc < 4){
            std::cerr << "Usage: " << argv[0] << "handshake <file.torent> <ip:port>" << std::endl;
            return 1;   
        }

        std::string file_name = argv[2]; 
        std::string peer_addr = argv[3];
        std::string buffer = read_file(file_name);
        json torrent = decode_bencoded_value(buffer);
        json info_dict = torrent["info"];
        std::string bencoded_info = json_to_bencode(info_dict);

        // Raw 20-byte SHA1 info hash
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char *>(bencoded_info.c_str()), bencoded_info.size(), hash);
        std::string info_hash(reinterpret_cast<char *>(hash), 20);

        // Generate peer ID
        std::string peer_id = generate_peer_id();

        // Build the handshake
        std::string handshake;
        handshake += static_cast<char>(19); // 1 byte length
        handshake += "BitTorrent protocol"; // 19 bytes protocol name
        handshake += std::string(8, '\0'); // 8 reserved bytes
        handshake += info_hash; // 20 bytes info hash
        handshake += peer_id; // 20 bytes peer ID

        // Extract IP and port
        size_t colon_pos = peer_addr.find(":");
        if (colon_pos == std::string::npos) {
            std::cerr << "Invalid peer address format. Use <ip>:<port>."<< std::endl;
            return 1;
        }
        std::string ip = peer_addr.substr(0, colon_pos);
        int port = std::stoi(peer_addr.substr(colon_pos + 1));

        // Setup TCP socket

            //  Function: socket(domain, type, protocol)
            // AF_INET → IPv4
            // SOCK_STREAM → TCP
            // 0 → Default protocol (for TCP, this is fine)
            // Returns: Socket file descriptor or -1 on failure.

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("Socket creation failed");
            return 1;
        }

        // Structure to store IPv4 address and port info. 

        // struct sockaddr_in {
        //     short sin_family;       // Address family (AF_INET)
        //     unsigned short sin_port;// Port number (in network byte order)
        //     struct in_addr sin_addr;// IP address
        //     char sin_zero[8];       // Padding (not used)
        // };

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;

        // converts the port from host byte order to network byte order (big-endian), which is needed for TCP/IP.
        server_addr.sin_port = htons(port);

        // Converts a string IP address (e.g., "104.21.13.78") to binary format and stores it in sin_addr
        inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr); 

        if (connect(sock, (sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Connection failed");
            close(sock);
            return 1;
        }

        // Send handshake
        ssize_t sent = send(sock, handshake.c_str(), handshake.size(), 0);
        if (sent < 0) {
            perror("Send failed");
            close(sock);
            return 1;
        }

        // Receive handshake response
        char response[68]; // 1 byte length + 19 bytes protocol + 8 reserved + 20 bytes info hash + 20 bytes peer ID
        ssize_t received = recv(sock, response, sizeof(response), 0);
        if (received < 0) {
            perror("Receive failed");
            close(sock);
            return 1;
        } 

        close(sock);

        // Extract and print peer ID as a hex string
        std::ostringstream oss;
        for (int i = 48; i < 68; ++i) { // Peer ID starts at byte 48
            oss << std::hex << std::setw(2) << std::setfill('0') << (static_cast<unsigned int>(static_cast<unsigned char>(response[i])));
        }
        
        std::cout << "Peer ID: " << oss.str() << std::endl;

    } 
    
    else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
