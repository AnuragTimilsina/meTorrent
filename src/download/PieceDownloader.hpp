#pragma once
#include "../core/TorrentInfo.hpp"
#include "../core/Peer.hpp"
#include "WorkQueue.hpp"
#include "DownloadProgress.hpp"
#include <vector>
#include <cstdint>

class PieceDownloader {
public:
    static bool download_piece_from_peer(const TorrentInfo& torrent_info, const Peer& peer, 
                                       int piece_index, std::vector<uint8_t>& piece_data);
    
    static void download_worker(const TorrentInfo& torrent_info, const std::vector<Peer>& peers,
                              WorkQueue& work_queue, DownloadProgress& progress);
};