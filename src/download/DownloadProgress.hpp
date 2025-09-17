#pragma once
#include "../core/TorrentInfo.hpp"
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>

class DownloadProgress {
private:
    std::vector<bool> completed_pieces;
    std::vector<std::vector<uint8_t>> piece_data;
    mutable std::mutex mtx;
    std::atomic<int> completed_count{0};
    int total_pieces;
    
public:
    DownloadProgress(int num_pieces, const TorrentInfo& torrent);
    
    void mark_piece_complete(int piece_index, const std::vector<uint8_t>& data);
    bool is_piece_complete(int piece_index) const;
    bool is_download_complete() const;
    void write_to_file(const std::string& filename);
    
    int get_completed_count() const;
    int get_total_count() const;
};