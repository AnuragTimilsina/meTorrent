#pragma once
#include "../core/Peer.hpp"
#include "../core/TorrentInfo.hpp"
#include <string>
#include <vector>
#include <array>
#include <cstdint>

class PeerConnection {
public:
    static int connect_to_peer(const Peer& peer);

    // updated: now returns the full handshake response
    static bool perform_handshake(int sock,
                                  const std::string& info_hash,
                                  const std::string& peer_id,
                                  std::array<char, 68>& response_out);

    static std::string extract_peer_id_from_handshake(const char* response);

    // Message handling
    static void send_message(int sockfd, uint8_t id, const std::vector<uint8_t>& payload = {});
    static void send_interested(int sockfd);
    static void send_request(int sockfd, int piece_index, int block_offset, int block_length);
    static std::vector<uint8_t> recv_message(int sockfd, uint8_t& id);

    // Utility
    static std::vector<bool> parse_bitfield(const std::string& bitfield_payload, size_t num_pieces);
};
