#include "PieceDownloader.hpp"
#include "../network/PeerConnection.hpp"
#include "../core/BitTorrentClient.hpp"
#include "../utils/CryptoUtils.hpp"
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <algorithm>
#include <cstring>
#include <iostream>

#define BLOCK_SIZE 16384 // 16 KiB

bool PieceDownloader::download_piece_from_peer(const TorrentInfo& torrent_info, const Peer& peer, 
                                                int piece_index, std::vector<uint8_t>& piece_data) {
    constexpr int block_size = BLOCK_SIZE;
    
    std::string peer_id = BitTorrentClient::generate_peer_id();
    
    int sock = PeerConnection::connect_to_peer(peer);
    if (sock < 0) {
        return false;
    }
    
    // Use 4-argument handshake version
    std::array<char, 68> handshake_response;
    if (!PeerConnection::perform_handshake(sock, torrent_info.info_hash_raw, peer_id, handshake_response)) {
        close(sock);
        return false;
    }
    
    int actual_piece_length = torrent_info.get_piece_size(piece_index);
    piece_data.resize(actual_piece_length);
    
    // Send interested immediately
    PeerConnection::send_interested(sock);
    
    // Setup phase
    bool peer_choking = true;
    std::vector<bool> bitfield;
    bool has_bitfield = false;
    
    auto start_time = std::chrono::steady_clock::now();
    auto timeout_duration = std::chrono::seconds(2); // Faster setup
    
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
            std::vector<uint8_t> payload = PeerConnection::recv_message(sock, msg_id);
            
            if (msg_id == 1) { // UNCHOKE
                peer_choking = false;
            } else if (msg_id == 5) { // BITFIELD
                bitfield = PeerConnection::parse_bitfield(
                    std::string(payload.begin(), payload.end()), 
                    torrent_info.piece_hashes.size()
                );
                has_bitfield = true;
                
                if (piece_index >= (int)bitfield.size() || !bitfield[piece_index]) {
                    close(sock);
                    return false;
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
        return false;
    }
    
    if (piece_index >= (int)bitfield.size() || !bitfield[piece_index]) {
        close(sock);
        return false;
    }
    
    // Download piece data
    int offset = 0;
    
    while (offset < actual_piece_length) {
        int req_len = std::min(block_size, actual_piece_length - offset);
        PeerConnection::send_request(sock, piece_index, offset, req_len);
        
        bool received_piece = false;
        
        try {
            uint8_t msg_id;
            std::vector<uint8_t> payload = PeerConnection::recv_message(sock, msg_id);
            
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
            return false;
        }
        
        if (!received_piece) {
            close(sock);
            return false;
        }
    }
    
    // Verify hash
    unsigned char actual_hash[SHA_DIGEST_LENGTH];
    SHA1(piece_data.data(), piece_data.size(), actual_hash);
    
    if (memcmp(actual_hash, torrent_info.piece_hashes[piece_index].data(), SHA_DIGEST_LENGTH) != 0) {
        close(sock);
        return false;
    }
    
    close(sock);
    return true;
}

void PieceDownloader::download_worker(const TorrentInfo& torrent_info, const std::vector<Peer>& peers,
                                      WorkQueue& work_queue, DownloadProgress& progress) {
    while (true) {
        int piece_index;
        if (!work_queue.get_piece(piece_index)) {
            break; // No more work
        }
        
        // Skip if piece already downloaded
        if (progress.is_piece_complete(piece_index)) {
            continue;
        }
        
        bool downloaded = false;
        
        // Try downloading from each peer until successful
        for (const auto& peer : peers) {
            try {
                std::vector<uint8_t> piece_data;
                if (download_piece_from_peer(torrent_info, peer, piece_index, piece_data)) {
                    progress.mark_piece_complete(piece_index, piece_data);
                    downloaded = true;
                    break;
                }
            } catch (const std::exception& e) {
                // Try next peer
                continue;
            }
        }
        
        // If download failed, put piece back in queue (keep retrying)
        if (!downloaded) {
            work_queue.add_piece(piece_index);
        }
    }
}
