#include "BitTorrentClient.hpp"
#include "../utils/BencodeParser.hpp"
#include "../utils/CryptoUtils.hpp"
#include "../utils/NetworkUtils.hpp"
#include "../network/TrackerClient.hpp"
#include "../download/PieceDownloader.hpp"
#include "../download/WorkQueue.hpp"
#include "../download/DownloadProgress.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <random>
#include <cstring>
#include <openssl/sha.h>
#include <chrono>
#include <thread>
#include <algorithm>
#include <iostream>
#include <iomanip>

TorrentInfo BitTorrentClient::parse_torrent(const std::string& filename) {
    std::string buffer = read_file(filename);
    json torrent = BencodeParser::decode_bencoded_value(buffer);
    json info_dict = torrent["info"];
    std::string bencoded_info = BencodeParser::json_to_bencode(info_dict);
    
    TorrentInfo info;
    info.tracker_url = torrent["announce"].get<std::string>();
    info.length = info_dict["length"].get<int64_t>();
    info.piece_length = info_dict["piece length"].get<int>();
    info.info_hash_hex = CryptoUtils::sha1_to_hex(bencoded_info);
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

MagnetInfo BitTorrentClient::parse_magnet_link(const std::string& magnet_url) {
    MagnetInfo info;
    
    // TODO: Implement magnet link parsing
    // Steps:
    // 1. Validate URL starts with "magnet:?"
    // 2. Extract query string after "magnet:?"
    // 3. Split query parameters by '&'
    // 4. For each parameter, split by '=' to get key-value pairs
    // 5. Process these parameters:
    //    - xt: extract info hash (remove "urn:btih:" prefix)
    //    - tr: extract and URL decode tracker URL
    //    - dn: extract and URL decode display name (optional)
    // 6. Convert hex info hash to raw bytes
    
    // Placeholder implementation - you need to implement this
    throw std::runtime_error("Magnet link parsing not implemented yet");
    
    return info;
}

void BitTorrentClient::download_file_single_peer(const TorrentInfo& torrent_info, const std::string& output_file) {
    std::vector<Peer> peers = TrackerClient::get_peers(torrent_info);
    
    if (peers.empty()) {
        throw std::runtime_error("No peers available from tracker");
    }
    
    std::cout << "Starting single-peer download with " << peers.size() << " available peers" << std::endl;
    
    int total_pieces = torrent_info.get_piece_count();
    DownloadProgress progress(total_pieces, torrent_info);
    
    // Try each peer until we find one that works
    bool found_working_peer = false;
    
    for (const auto& peer : peers) {
        std::cout << "Trying peer: " << peer.to_string() << std::endl;
        
        try {
            // Download all pieces from this peer
            for (int piece_index = 0; piece_index < total_pieces; ++piece_index) {
                if (progress.is_piece_complete(piece_index)) {
                    continue;
                }
                
                std::vector<uint8_t> piece_data;
                if (PieceDownloader::download_piece_from_peer(torrent_info, peer, piece_index, piece_data)) {
                    progress.mark_piece_complete(piece_index, piece_data);
                } else {
                    throw std::runtime_error("Failed to download piece " + std::to_string(piece_index));
                }
            }
            
            found_working_peer = true;
            break;
            
        } catch (const std::exception& e) {
            std::cerr << "Peer " << peer.to_string() << " failed: " << e.what() << std::endl;
            std::cerr << "Trying next peer..." << std::endl;
            continue;
        }
    }
    
    if (!found_working_peer) {
        throw std::runtime_error("Failed to download from any available peer");
    }
    
    if (progress.is_download_complete()) {
        progress.write_to_file(output_file);
        std::cout << "Download completed successfully!" << std::endl;
    } else {
        throw std::runtime_error("Download incomplete");
    }
}

void BitTorrentClient::download_file_multi_peer(const TorrentInfo& torrent_info, const std::string& output_file, int num_workers) {
    std::vector<Peer> peers = TrackerClient::get_peers(torrent_info);
    
    if (peers.empty()) {
        throw std::runtime_error("No peers available from tracker");
    }
    
    std::cout << "Starting multi-peer download with " << peers.size() << " peers and " 
              << num_workers << " workers" << std::endl;
    
    int total_pieces = torrent_info.get_piece_count();
    WorkQueue work_queue;
    DownloadProgress progress(total_pieces, torrent_info);
    
    // Add all pieces to work queue
    for (int i = 0; i < total_pieces; ++i) {
        work_queue.add_piece(i);
    }
    
    // Start worker threads
    std::vector<std::thread> workers;
    for (int i = 0; i < num_workers; ++i) {
        workers.emplace_back(PieceDownloader::download_worker, std::cref(torrent_info), std::cref(peers),
                           std::ref(work_queue), std::ref(progress));
    }
    
    // Monitor progress (minimal to avoid overhead)
    while (!progress.is_download_complete()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Very fast checking
    }
    
    // Signal workers to stop and wait for them
    work_queue.mark_finished();
    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    if (progress.is_download_complete()) {
        progress.write_to_file(output_file);
        std::cout << "Multi-peer download completed successfully!" << std::endl;
    } else {
        throw std::runtime_error("Download incomplete - " + std::to_string(progress.get_completed_count()) 
                               + "/" + std::to_string(progress.get_total_count()) + " pieces downloaded");
    }
}

void BitTorrentClient::download_piece(const TorrentInfo& torrent_info, const Peer& peer, int piece_index, const std::string& output_file) {
    std::vector<uint8_t> piece_data;
    
    if (!PieceDownloader::download_piece_from_peer(torrent_info, peer, piece_index, piece_data)) {
        throw std::runtime_error("Failed to download piece from peer");
    }
    
    // Save piece
    std::string filename = output_file.empty() ? "piece_" + std::to_string(piece_index) + ".bin" : output_file;
    std::ofstream out(filename, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to create output file: " + filename);
    }
    out.write(reinterpret_cast<const char*>(piece_data.data()), piece_data.size());
    out.close();
    
    std::cout << "Piece " << piece_index << " downloaded and verified." << std::endl;
}

std::string BitTorrentClient::generate_peer_id() {
    std::string peer_id = PEER_ID_PREFIX;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    while (peer_id.size() < 20) {
        peer_id += static_cast<char>(dis(gen));
    }
    return peer_id;
}

std::string BitTorrentClient::read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}