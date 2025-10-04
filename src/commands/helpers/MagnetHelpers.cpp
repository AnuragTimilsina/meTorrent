#include "MagnetHelpers.hpp"
#include "../../core/BitTorrentClient.hpp"
#include "../../network/PeerConnection.hpp"
#include "../../download/PieceDownloader.hpp"
#include "../../utils/CryptoUtils.hpp"
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <cstring>

namespace MagnetHelpers {

bool retrieve_metadata_from_magnet(
    const MagnetInfo& magnet_info,
    const std::vector<Peer>& peers,
    TorrentInfo& torrent_info
) {
    for (const auto& peer : peers) {
        try {
            std::string peer_id = BitTorrentClient::generate_peer_id();
            
            // Connect and handshake
            int sock = PeerConnection::connect_to_peer(peer);
            if (sock < 0) continue;
            
            std::array<char, 68> handshake_response{};
            if (!PeerConnection::perform_handshake(sock, magnet_info.info_hash_raw, 
                                                   peer_id, handshake_response)) {
                close(sock);
                continue;
            }
            
            // Read initial message (bitfield, etc.)
            try {
                uint8_t msg_id = 0;
                PeerConnection::recv_message(sock, msg_id);
            } catch (...) {
                // Not critical, continue
            }
            
            // Check extension support
            if (handshake_response.size() < 68) {
                close(sock);
                continue;
            }
            
            unsigned char reserved5 = static_cast<unsigned char>(handshake_response[25]);
            if ((reserved5 & 0x10) == 0) {
                close(sock);
                continue;
            }
            
            // Send extension handshake
            json ext_dict;
            ext_dict["m"] = {{"ut_metadata", 1}};
            std::string bencoded = BencodeParser::json_to_bencode(ext_dict);
            
            std::vector<uint8_t> ext_payload;
            ext_payload.push_back(0); // extension handshake ID
            ext_payload.insert(ext_payload.end(), bencoded.begin(), bencoded.end());
            PeerConnection::send_message(sock, 20, ext_payload);
            
            // Receive extension handshake
            uint8_t resp_msg_id = 0;
            auto resp_payload = PeerConnection::recv_message(sock, resp_msg_id);
            
            if (resp_msg_id != 20 || resp_payload.empty() || resp_payload[0] != 0) {
                close(sock);
                continue;
            }
            
            std::string benc_str(reinterpret_cast<char*>(resp_payload.data() + 1),
                                resp_payload.size() - 1);
            json peer_ext_dict = BencodeParser::decode_bencoded_value(benc_str);
            
            if (!peer_ext_dict.contains("m") || 
                !peer_ext_dict["m"].is_object() ||
                !peer_ext_dict["m"].contains("ut_metadata")) {
                close(sock);
                continue;
            }
            
            uint8_t peer_ut_metadata_id = peer_ext_dict["m"]["ut_metadata"].get<int>();
            
            // Request metadata piece 0
            json request_dict;
            request_dict["msg_type"] = 0;
            request_dict["piece"] = 0;
            
            std::string bencoded_request = BencodeParser::json_to_bencode(request_dict);
            std::vector<uint8_t> request_payload;
            request_payload.push_back(peer_ut_metadata_id);
            request_payload.insert(request_payload.end(), 
                                 bencoded_request.begin(), 
                                 bencoded_request.end());
            
            PeerConnection::send_message(sock, 20, request_payload);
            
            // Receive metadata response
            uint8_t metadata_msg_id = 0;
            auto metadata_payload = PeerConnection::recv_message(sock, metadata_msg_id);
            
            if (metadata_msg_id != 20 || metadata_payload.empty()) {
                close(sock);
                continue;
            }
            
            std::string full_payload(reinterpret_cast<char*>(metadata_payload.data() + 1),
                                    metadata_payload.size() - 1);
            
            // Split dictionary and metadata
            size_t pos = 0;
            json metadata_dict = BencodeParser::decode_bencoded_value(full_payload, pos);
            
            if (!metadata_dict.contains("msg_type") || 
                metadata_dict["msg_type"].get<int>() != 1) {
                close(sock);
                continue;
            }
            
            std::string metadata_content = full_payload.substr(pos);
            json info_dict = BencodeParser::decode_bencoded_value(metadata_content);
            
            // Validate hash
            std::string reencoded_info = BencodeParser::json_to_bencode(info_dict);
            std::string computed_hash = CryptoUtils::sha1_to_hex(reencoded_info);
            
            if (computed_hash != magnet_info.info_hash_hex) {
                close(sock);
                continue;
            }
            
            // Build TorrentInfo
            torrent_info.tracker_url = magnet_info.tracker_url;
            torrent_info.length = info_dict["length"].get<int64_t>();
            torrent_info.piece_length = info_dict["piece length"].get<int>();
            torrent_info.info_hash_hex = magnet_info.info_hash_hex;
            torrent_info.info_hash_raw = magnet_info.info_hash_raw;
            torrent_info.info_dict = info_dict;
            
            // Parse piece hashes
            std::string pieces_raw = info_dict["pieces"].get<std::string>();
            for (size_t i = 0; i < pieces_raw.size(); i += 20) {
                std::array<uint8_t, 20> piece_hash;
                memcpy(piece_hash.data(), pieces_raw.data() + i, 20);
                torrent_info.piece_hashes.push_back(piece_hash);
            }
            
            close(sock);
            return true;
            
        } catch (const std::exception& e) {
            continue;
        }
    }
    
    return false;
}

void print_metadata_info(const MagnetInfo& magnet_info, const json& info_dict) {
    std::cout << "Tracker URL: " << magnet_info.tracker_url << std::endl;
    
    if (info_dict.contains("length"))
        std::cout << "Length: " << info_dict["length"].get<int64_t>() << std::endl;
    
    std::cout << "Info Hash: " << magnet_info.info_hash_hex << std::endl;
    
    if (info_dict.contains("piece length"))
        std::cout << "Piece Length: " << info_dict["piece length"].get<int>() << std::endl;
    
    if (info_dict.contains("pieces")) {
        std::cout << "Piece Hashes:" << std::endl;
        std::string pieces_raw = info_dict["pieces"].get<std::string>();
        for (size_t i = 0; i < pieces_raw.size(); i += 20) {
            std::string piece_hash_hex;
            for (int j = 0; j < 20 && (i + j) < pieces_raw.size(); ++j) {
                char hex_byte[3];
                sprintf(hex_byte, "%02x", static_cast<unsigned char>(pieces_raw[i + j]));
                piece_hash_hex += hex_byte;
            }
            std::cout << piece_hash_hex << std::endl;
        }
    }
}

bool download_single_piece(
    const TorrentInfo& torrent_info,
    const std::vector<Peer>& peers,
    int piece_index,
    const std::string& output_file
) {
    std::vector<uint8_t> piece_data;
    
    for (const auto& peer : peers) {
        try {
            if (PieceDownloader::download_piece_from_peer(
                torrent_info, peer, piece_index, piece_data)) {
                
                std::ofstream out(output_file, std::ios::binary);
                if (!out) {
                    std::cerr << "Failed to create output file: " << output_file << std::endl;
                    return false;
                }
                
                out.write(reinterpret_cast<const char*>(piece_data.data()), 
                         piece_data.size());
                out.close();
                
                std::cout << "Piece " << piece_index << " downloaded to " 
                          << output_file << std::endl;
                return true;
            }
        } catch (const std::exception& e) {
            continue;
        }
    }
    
    return false;
}

} // namespace MagnetHelpers