#pragma once
#include "../core/TorrentInfo.hpp"
#include "../core/MagnetInfo.hpp"
#include "../core/Peer.hpp"
#include <vector>
#include <string>

class TrackerClient {
public:
    static std::vector<Peer> get_peers(const TorrentInfo& torrent_info);
    static std::vector<Peer> get_peers(const MagnetInfo& magnet_info);  // NEW overload

private:
    static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp);
    static std::vector<Peer> parse_peers_compact(const std::string& peers_compact);
};
