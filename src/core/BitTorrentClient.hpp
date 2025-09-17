#pragma once
#include "TorrentInfo.hpp"
#include "MagnetInfo.hpp"
#include "Peer.hpp"
#include <string>
#include <vector>

class BitTorrentClient {
private:
    static constexpr int DEFAULT_PORT = 6881;
    static constexpr const char* PEER_ID_PREFIX = "-PC0001-";
    
public:
    // Factory methods
    static TorrentInfo parse_torrent(const std::string& filename);
    static MagnetInfo parse_magnet_link(const std::string& magnet_url);
    
    // High-level operations
    static void download_file_single_peer(const TorrentInfo& torrent_info, const std::string& output_file);
    static void download_file_multi_peer(const TorrentInfo& torrent_info, const std::string& output_file, int num_workers = 4);
    static void download_piece(const TorrentInfo& torrent_info, const Peer& peer, int piece_index, const std::string& output_file = "");
    
    // Utility functions
    static std::string generate_peer_id();
    static std::string read_file(const std::string& filename);
};