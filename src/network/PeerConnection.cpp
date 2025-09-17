#include "PeerConnection.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>

int PeerConnection::connect_to_peer(const Peer& peer) {
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


bool PeerConnection::perform_handshake(int sock,
                                       const std::string& info_hash,
                                       const std::string& peer_id,
                                       std::array<char, 68>& response_out) {
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

    size_t total_read = 0;
    while (total_read < response_out.size()) {
        ssize_t n = recv(sock, response_out.data() + total_read,
                         response_out.size() - total_read, 0);
        if (n <= 0) {
            std::cerr << "Failed to receive complete handshake." << std::endl;
            return false;
        }
        total_read += n;
    }

    std::string received_info_hash(response_out.data() + 28, 20);
    if (received_info_hash != info_hash) {
        std::cerr << "Info hash mismatch in handshake response." << std::endl;
        return false;
    }

    return true;
}


std::string PeerConnection::extract_peer_id_from_handshake(const char* response) {
    std::ostringstream oss;
    for (int i = 48; i < 68; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << (static_cast<unsigned int>(static_cast<unsigned char>(response[i])));
    }
    return oss.str();
}

void PeerConnection::send_message(int sockfd, uint8_t id, const std::vector<uint8_t>& payload) {
    uint32_t length = htonl(1 + payload.size());
    write(sockfd, &length, 4);
    write(sockfd, &id, 1);
    if (!payload.empty()) write(sockfd, payload.data(), payload.size());
}

void PeerConnection::send_interested(int sockfd) {
    send_message(sockfd, 2);
}

void PeerConnection::send_request(int sockfd, int piece_index, int block_offset, int block_length) {
    std::vector<uint8_t> payload(12);
    *(uint32_t*)&payload[0] = htonl(piece_index);
    *(uint32_t*)&payload[4] = htonl(block_offset);
    *(uint32_t*)&payload[8] = htonl(block_length);
    send_message(sockfd, 6, payload);
}

std::vector<uint8_t> PeerConnection::recv_message(int sockfd, uint8_t& id) {
    // Helper function to read exact number of bytes with timeout
    auto read_exact = [&](void* buf, size_t count) -> bool {
        size_t total_read = 0;
        char* buffer = static_cast<char*>(buf);
        
        while (total_read < count) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(sockfd, &read_fds);
            
            struct timeval timeout;
            timeout.tv_sec = 2;  // Very aggressive timeout for speed
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

std::vector<bool> PeerConnection::parse_bitfield(const std::string& bitfield_payload, size_t num_pieces) {
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