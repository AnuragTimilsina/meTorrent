#include <iostream>
#include <openssl/sha.h>
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
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <chrono>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

#define BLOCK_SIZE 16384 // 16 KiB

// === STRUCTS AND CLASSES ===

struct Peer {
    std::string ip;
    uint16_t port;
    
    Peer(const std::string& ip, uint16_t port) : ip(ip), port(port) {}
    
    std::string to_string() const {
        return ip + ":" + std::to_string(port);
    }
};

struct TorrentInfo {
    std::string tracker_url;
    int64_t length;
    int piece_length;
    std::string info_hash_hex;
    std::string info_hash_raw;
    std::vector<std::array<uint8_t, 20>> piece_hashes;
    json info_dict;
    
    void print_info() const {
        std::cout << "Tracker URL: " << tracker_url << std::endl;
        std::cout << "Length: " << length << std::endl;
        std::cout << "Info Hash: " << info_hash_hex << std::endl;
        std::cout << "Piece Length: " << piece_length << std::endl;
        std::cout << "Piece Hashes: " << std::endl;
        
        for (const auto& hash : piece_hashes) {
            std::ostringstream oss;
            for (unsigned char c : hash) {
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
            }
            std::cout << oss.str() << std::endl;
        }
    }
};

class BitTorrentClient {
private:
    static constexpr int DEFAULT_PORT = 6881;
    static constexpr const char* PEER_ID_PREFIX = "-PC0001-";
    
public:
    // === UTILITY FUNCTIONS ===
    
    static std::string sha1_to_hex(const std::string& input) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
        std::ostringstream oss;
        for (int i = 0; i < SHA_DIGEST_LENGTH; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        return oss.str();
    }
    
    static std::string url_encode(const std::string& value) {
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
    
    static std::string generate_peer_id() {
        std::string peer_id = PEER_ID_PREFIX;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        while (peer_id.size() < 20) {
            peer_id += static_cast<char>(dis(gen));
        }
        return peer_id;
    }
    
    static std::string read_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open file: " + filename);
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }
    
    // === TORRENT PARSING ===
    
    static TorrentInfo parse_torrent(const std::string& filename) {
        std::string buffer = read_file(filename);
        json torrent = decode_bencoded_value(buffer);
        json info_dict = torrent["info"];
        std::string bencoded_info = json_to_bencode(info_dict);
        
        TorrentInfo info;
        info.tracker_url = torrent["announce"].get<std::string>();
        info.length = info_dict["length"].get<int64_t>();
        info.piece_length = info_dict["piece length"].get<int>();
        info.info_hash_hex = sha1_to_hex(bencoded_info);
        info.info_dict = info_dict;
        
        // Generate raw hash
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(bencoded_info.c_str()), bencoded_info.size(), hash);
        info.info_hash_raw = std::string(reinterpret_cast<char*>(hash), SHA_DIGEST_LENGTH);
        
        // Parse piece hashes
        std::string pieces_raw = info_dict["pieces"];
        for (size_t i = 0; i < pieces_raw.size(); i += 20) {
            std::array<uint8_t, 20> piece_hash;
            memcpy(piece_hash.data(), pieces_raw.data() + i, 20);
            info.piece_hashes.push_back(piece_hash);
        }
        
        return info;
    }
    
    // === TRACKER COMMUNICATION ===
    
    static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t total_size = size * nmemb;
        std::string* output = static_cast<std::string*>(userp);
        output->append((char*)contents, total_size);
        return total_size;
    }
    
    static std::vector<Peer> get_peers(const TorrentInfo& torrent_info) {
        std::string peer_id = generate_peer_id();
        
        std::ostringstream url;
        url << torrent_info.tracker_url
            << "?info_hash=" << url_encode(torrent_info.info_hash_raw)
            << "&peer_id=" << url_encode(peer_id)
            << "&port=" << DEFAULT_PORT
            << "&uploaded=0&downloaded=0"
            << "&left=" << torrent_info.length
            << "&compact=1";
        
        CURL* curl = curl_easy_init();
        std::string response;
        
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }
        
        curl_easy_setopt(curl, CURLOPT_URL, url.str().c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if (res != CURLE_OK) {
            throw std::runtime_error("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
        }
        
        json tracker_response = decode_bencoded_value(response);
        
        if (!tracker_response.contains("peers") || !tracker_response["peers"].is_string()) {
            throw std::runtime_error("Tracker response does not contain valid peers");
        }
        
        return parse_peers_compact(tracker_response["peers"]);
    }
    
    static std::vector<Peer> parse_peers_compact(const std::string& peers_compact) {
        std::vector<Peer> peers;
        
        for (size_t i = 0; i + 6 <= peers_compact.size(); i += 6) {
            uint8_t ip_bytes[4];
            uint16_t port;
            
            memcpy(ip_bytes, &peers_compact[i], 4);
            memcpy(&port, &peers_compact[i + 4], 2);
            
            std::string ip = std::to_string(ip_bytes[0]) + "." +
                           std::to_string(ip_bytes[1]) + "." +
                           std::to_string(ip_bytes[2]) + "." +
                           std::to_string(ip_bytes[3]);
            
            port = ntohs(port);
            peers.emplace_back(ip, port);
        }
        
        return peers;
    }
    
    // === PEER COMMUNICATION ===
    
    static int connect_to_peer(const Peer& peer) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
            return -1;
        }
        
        // Set socket to non-blocking for faster connection timeout
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(peer.port);
        
        if (inet_pton(AF_INET, peer.ip.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "Invalid IP address: " << peer.ip << std::endl;
            close(sock);
            return -1;
        }
        
        int result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
        if (result < 0 && errno != EINPROGRESS) {
            std::cerr << "Connection to " << peer.to_string() << " failed: " << strerror(errno) << std::endl;
            close(sock);
            return -1;
        }
        
        // Wait for connection with short timeout
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 3;  // 3 second connection timeout
        timeout.tv_usec = 0;
        
        result = select(sock + 1, NULL, &write_fds, NULL, &timeout);
        if (result <= 0) {
            close(sock);
            return -1;
        }
        
        // Check if connection was successful
        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            close(sock);
            return -1;
        }
        
        // Set back to blocking mode
        fcntl(sock, F_SETFL, flags);
        
        return sock;
    }
    
    static bool perform_handshake(int sock, const std::string& info_hash, const std::string& peer_id) {
        std::string handshake;
        handshake += static_cast<char>(19);
        handshake += "BitTorrent protocol";
        handshake += std::string(8, '\0');
        handshake += info_hash;
        handshake += peer_id;
        
        ssize_t sent = send(sock, handshake.c_str(), handshake.size(), 0);
        if (sent != static_cast<ssize_t>(handshake.size())) {
            std::cerr << "Failed to send handshake." << std::endl;
            return false;
        }
        
        char response[68];
        ssize_t received = recv(sock, response, sizeof(response), 0);
        if (received != 68) {
            std::cerr << "Failed to receive complete handshake." << std::endl;
            return false;
        }
        
        std::string received_info_hash(response + 28, 20);
        if (received_info_hash != info_hash) {
            std::cerr << "Info hash mismatch in handshake response." << std::endl;
            return false;
        }
        
        return true;
    }
    
    static std::string extract_peer_id_from_handshake(const char* response) {
        std::ostringstream oss;
        for (int i = 48; i < 68; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') 
                << (static_cast<unsigned int>(static_cast<unsigned char>(response[i])));
        }
        return oss.str();
    }
    
    // === PIECE DOWNLOAD ===
    
    static void send_message(int sockfd, uint8_t id, const std::vector<uint8_t>& payload = {}) {
        uint32_t length = htonl(1 + payload.size());
        write(sockfd, &length, 4);
        write(sockfd, &id, 1);
        if (!payload.empty()) write(sockfd, payload.data(), payload.size());
    }
    
    static void send_interested(int sockfd) {
        send_message(sockfd, 2);
    }
    
    static void send_request(int sockfd, int piece_index, int block_offset, int block_length) {
        std::vector<uint8_t> payload(12);
        *(uint32_t*)&payload[0] = htonl(piece_index);
        *(uint32_t*)&payload[4] = htonl(block_offset);
        *(uint32_t*)&payload[8] = htonl(block_length);
        send_message(sockfd, 6, payload);
    }
    
    static std::vector<uint8_t> recv_message(int sockfd, uint8_t& id) {
        // Helper function to read exact number of bytes with timeout
        auto read_exact = [&](void* buf, size_t count) -> bool {
            size_t total_read = 0;
            char* buffer = static_cast<char*>(buf);
            
            while (total_read < count) {
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(sockfd, &read_fds);
                
                struct timeval timeout;
                timeout.tv_sec = 5;  // 5 seconds timeout
                timeout.tv_usec = 0;
                
                int result = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
                if (result <= 0) {
                    return false; // Timeout or error
                }
                
                ssize_t bytes_read = read(sockfd, buffer + total_read, count - total_read);
                if (bytes_read <= 0) {
                    return false; // Connection closed or error
                }
                total_read += bytes_read;
            }
            return true;
        };
        
        // Read message length
        uint8_t len_buf[4];
        if (!read_exact(len_buf, 4)) {
            throw std::runtime_error("Failed to read message length");
        }
        uint32_t length = ntohl(*(uint32_t*)len_buf);
        
        if (length == 0) {
            id = 0xFF; // Keep-alive message
            return {};
        }
        
        if (length > 1000000) { // Sanity check
            throw std::runtime_error("Invalid message length: " + std::to_string(length));
        }
        
        // Read message ID
        if (!read_exact(&id, 1)) {
            throw std::runtime_error("Failed to read message ID");
        }
        
        // Read payload
        std::vector<uint8_t> payload(length - 1);
        if (payload.size() > 0) {
            if (!read_exact(payload.data(), payload.size())) {
                throw std::runtime_error("Failed to read complete payload");
            }
        }
        return payload;
    }
    
    static std::vector<bool> parse_bitfield(const std::string& bitfield_payload, size_t num_pieces) {
        std::vector<bool> bitfield(num_pieces, false);
        
        for (size_t i = 0; i < num_pieces; ++i) {
            size_t byte_index = i / 8;
            size_t bit_index = 7 - (i % 8);
            if (byte_index < bitfield_payload.size()) {
                if (bitfield_payload[byte_index] & (1 << bit_index)) {
                    bitfield[i] = true;
                }
            }
        }
        return bitfield;
    }
    
    static void download_piece(const TorrentInfo& torrent_info, const Peer& peer, int piece_index, const std::string& output_file = "") {
        constexpr int block_size = BLOCK_SIZE;
        
        std::string peer_id = generate_peer_id();
        
        int sock = connect_to_peer(peer);
        if (sock < 0) {
            throw std::runtime_error("Failed to connect to peer");
        }
        
        if (!perform_handshake(sock, torrent_info.info_hash_raw, peer_id)) {
            close(sock);
            throw std::runtime_error("Handshake failed");
        }
        
        // Calculate actual piece length (last piece might be smaller)
        int64_t total_length = torrent_info.length;
        int actual_piece_length = torrent_info.piece_length;
        
        // Check if this is the last piece
        int total_pieces = (total_length + torrent_info.piece_length - 1) / torrent_info.piece_length;
        if (piece_index == total_pieces - 1) {
            // Last piece might be smaller
            actual_piece_length = total_length % torrent_info.piece_length;
            if (actual_piece_length == 0) {
                actual_piece_length = torrent_info.piece_length;
            }
        }
        
        // Send interested immediately
        send_interested(sock);
        
        // Fast initial message processing
        bool peer_choking = true;
        std::vector<bool> bitfield;
        bool has_bitfield = false;
        
        // Quick setup with timeout
        auto start_time = std::chrono::steady_clock::now();
        auto timeout_duration = std::chrono::seconds(5);
        
        while (peer_choking || !has_bitfield) {
            auto current_time = std::chrono::steady_clock::now();
            if (current_time - start_time > timeout_duration) {
                if (!has_bitfield) {
                    bitfield.assign(torrent_info.piece_hashes.size(), true);
                    has_bitfield = true;
                }
                break;
            }
            
            try {
                uint8_t msg_id;
                std::vector<uint8_t> payload = recv_message(sock, msg_id);
                
                if (msg_id == 1) { // UNCHOKE
                    peer_choking = false;
                } else if (msg_id == 5) { // BITFIELD
                    bitfield = parse_bitfield(std::string(payload.begin(), payload.end()), 
                                            torrent_info.piece_hashes.size());
                    has_bitfield = true;
                    
                    if (piece_index >= (int)bitfield.size() || !bitfield[piece_index]) {
                        close(sock);
                        throw std::runtime_error("Peer does not have the requested piece");
                    }
                } else if (msg_id == 4) { // HAVE
                    if (!has_bitfield) {
                        bitfield.assign(torrent_info.piece_hashes.size(), false);
                        has_bitfield = true;
                    }
                    if (payload.size() >= 4) {
                        uint32_t piece_idx = ntohl(*(uint32_t*)payload.data());
                        if (piece_idx < bitfield.size()) {
                            bitfield[piece_idx] = true;
                        }
                    }
                } else if (msg_id == 0xFF) {
                    continue; // Keep-alive
                }
                
                if (!peer_choking && has_bitfield && 
                    piece_index < (int)bitfield.size() && bitfield[piece_index]) {
                    break;
                }
                
            } catch (const std::exception& e) {
                if (!has_bitfield) {
                    bitfield.assign(torrent_info.piece_hashes.size(), true);
                    has_bitfield = true;
                }
                break;
            }
        }
        
        if (peer_choking) {
            close(sock);
            throw std::runtime_error("Peer is still choking");
        }
        
        if (piece_index >= (int)bitfield.size() || !bitfield[piece_index]) {
            close(sock);
            throw std::runtime_error("Peer does not have the requested piece");
        }
        
        // Download piece data
        std::vector<uint8_t> piece_data(actual_piece_length, 0);
        int offset = 0;
        
        while (offset < actual_piece_length) {
            int req_len = std::min(block_size, actual_piece_length - offset);
            send_request(sock, piece_index, offset, req_len);
            
            bool received_piece = false;
            
            try {
                uint8_t msg_id;
                std::vector<uint8_t> payload = recv_message(sock, msg_id);
                
                if (msg_id == 7 && payload.size() >= 8) { // PIECE message
                    int idx = ntohl(*(uint32_t*)&payload[0]);
                    int begin = ntohl(*(uint32_t*)&payload[4]);
                    
                    if (idx == piece_index && begin == offset) {
                        int data_len = payload.size() - 8;
                        if (begin + data_len <= actual_piece_length) {
                            std::copy(payload.begin() + 8, payload.end(), piece_data.begin() + begin);
                            offset += data_len;
                            received_piece = true;
                        }
                    }
                }
            } catch (const std::exception& e) {
                close(sock);
                throw std::runtime_error("Failed to receive piece block: " + std::string(e.what()));
            }
            
            if (!received_piece) {
                close(sock);
                throw std::runtime_error("Did not receive expected piece block");
            }
        }
        
        // Verify hash
        unsigned char actual_hash[SHA_DIGEST_LENGTH];
        SHA1(piece_data.data(), piece_data.size(), actual_hash);
        
        if (memcmp(actual_hash, torrent_info.piece_hashes[piece_index].data(), SHA_DIGEST_LENGTH) != 0) {
            close(sock);
            throw std::runtime_error("Piece hash mismatch! Corrupted data");
        }
        
        // Save piece
        std::string filename = output_file.empty() ? "piece_" + std::to_string(piece_index) + ".bin" : output_file;
        std::ofstream out(filename, std::ios::binary);
        if (!out) {
            close(sock);
            throw std::runtime_error("Failed to create output file: " + filename);
        }
        out.write(reinterpret_cast<const char*>(piece_data.data()), piece_data.size());
        out.close();
        
        std::cout << "Piece " << piece_index << " downloaded and verified." << std::endl;
        close(sock);
    }
    
    // === BENCODE FUNCTIONS ===
    
    static json decode_bencoded_value(const std::string& s, size_t& pos) {
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
    
    static json decode_bencoded_value(const std::string& s) {
        size_t pos = 0;
        return decode_bencoded_value(s, pos);
    }
    
    static std::string json_to_bencode(const json& j) {
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
};

// === COMMAND HANDLERS ===

void handle_decode(const std::vector<std::string>& args) {
    if (args.size() < 1) {
        std::cerr << "Usage: decode <encoded_value>" << std::endl;
        return;
    }
    
    json decoded_value = BitTorrentClient::decode_bencoded_value(args[0]);
    std::cout << decoded_value.dump() << std::endl;
}

void handle_info(const std::vector<std::string>& args) {
    if (args.size() < 1) {
        std::cerr << "Usage: info <file.torrent>" << std::endl;
        return;
    }
    
    try {
        TorrentInfo info = BitTorrentClient::parse_torrent(args[0]);
        info.print_info();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void handle_peers(const std::vector<std::string>& args) {
    if (args.size() < 1) {
        std::cerr << "Usage: peers <file.torrent>" << std::endl;
        return;
    }
    
    try {
        TorrentInfo info = BitTorrentClient::parse_torrent(args[0]);
        std::vector<Peer> peers = BitTorrentClient::get_peers(info);
        
        for (const auto& peer : peers) {
            std::cout << peer.to_string() << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void handle_handshake(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "Usage: handshake <file.torrent> <ip:port>" << std::endl;
        return;
    }
    
    try {
        TorrentInfo info = BitTorrentClient::parse_torrent(args[0]);
        
        // Parse peer address
        std::string peer_addr = args[1];
        size_t colon_pos = peer_addr.find(":");
        if (colon_pos == std::string::npos) {
            std::cerr << "Invalid peer address format. Use <ip>:<port>." << std::endl;
            return;
        }
        
        std::string ip = peer_addr.substr(0, colon_pos);
        int port = std::stoi(peer_addr.substr(colon_pos + 1));
        Peer peer(ip, port);
        
        std::string peer_id = BitTorrentClient::generate_peer_id();
        
        int sock = BitTorrentClient::connect_to_peer(peer);
        if (sock < 0) {
            std::cerr << "Failed to connect to peer." << std::endl;
            return;
        }
        
        // Build handshake
        std::string handshake;
        handshake += static_cast<char>(19);
        handshake += "BitTorrent protocol";
        handshake += std::string(8, '\0');
        handshake += info.info_hash_raw;
        handshake += peer_id;
        
        ssize_t sent = send(sock, handshake.c_str(), handshake.size(), 0);
        if (sent < 0) {
            perror("Send failed");
            close(sock);
            return;
        }
        
        char response[68];
        ssize_t received = recv(sock, response, sizeof(response), 0);
        if (received < 0) {
            perror("Receive failed");
            close(sock);
            return;
        }
        
        close(sock);
        
        std::string peer_id_hex = BitTorrentClient::extract_peer_id_from_handshake(response);
        std::cout << "Peer ID: " << peer_id_hex << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void handle_download_piece(const std::vector<std::string>& args) {
    if (args.size() < 4 || args[0] != "-o") {
        std::cerr << "Usage: download_piece -o <output_file> <file.torrent> <piece_index>" << std::endl;
        return;
    }
    
    std::string output_file = args[1];
    std::string torrent_file = args[2];
    int piece_index = std::stoi(args[3]);
    
    try {
        TorrentInfo info = BitTorrentClient::parse_torrent(torrent_file);
        std::vector<Peer> peers = BitTorrentClient::get_peers(info);
        
        if (peers.empty()) {
            std::cerr << "No peers available from tracker." << std::endl;
            return;
        }
        
        // Try only the first peer to avoid timeout
        BitTorrentClient::download_piece(info, peers[0], piece_index, output_file);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

// === MAIN ===

int main(int argc, char* argv[]) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command> <args>" << std::endl;
        std::cerr << "Commands: decode, info, peers, handshake, download_piece" << std::endl;
        return 1;
    }
    
    std::string command = argv[1];
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    
    if (command == "decode") {
        handle_decode(args);
    } else if (command == "info") {
        handle_info(args);
    } else if (command == "peers") {
        handle_peers(args);
    } else if (command == "handshake") {
        handle_handshake(args);
    } else if (command == "download_piece") {
        handle_download_piece(args);
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        std::cerr << "Available commands: decode, info, peers, handshake, download_piece" << std::endl;
        return 1;
    }
    
    return 0;
}