#include "DownloadProgress.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

DownloadProgress::DownloadProgress(int num_pieces, const TorrentInfo& torrent) 
    : completed_pieces(num_pieces, false), piece_data(num_pieces), total_pieces(num_pieces) {
    
    // Pre-allocate piece data vectors
    for (int i = 0; i < num_pieces; ++i) {
        piece_data[i].resize(torrent.get_piece_size(i));
    }
}

void DownloadProgress::mark_piece_complete(int piece_index, const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mtx);
    if (!completed_pieces[piece_index]) {
        completed_pieces[piece_index] = true;
        piece_data[piece_index] = data;
        completed_count++;
        
        // Reduced logging for speed
        if (completed_count % 3 == 0 || completed_count == total_pieces) {
            std::cout << "Downloaded piece " << piece_index << " (" 
                      << completed_count << "/" << total_pieces << ")" << std::endl;
        }
    }
}

bool DownloadProgress::is_piece_complete(int piece_index) const {
    std::lock_guard<std::mutex> lock(mtx);
    return completed_pieces[piece_index];
}

bool DownloadProgress::is_download_complete() const {
    return completed_count == total_pieces;
}

void DownloadProgress::write_to_file(const std::string& filename) {
    std::lock_guard<std::mutex> lock(mtx);
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to create output file: " + filename);
    }
    
    for (int i = 0; i < total_pieces; ++i) {
        if (!completed_pieces[i]) {
            throw std::runtime_error("Cannot write file: piece " + std::to_string(i) + " not downloaded");
        }
        file.write(reinterpret_cast<const char*>(piece_data[i].data()), piece_data[i].size());
    }
    
    file.close();
    std::cout << "File assembled and saved to: " << filename << std::endl;
}

int DownloadProgress::get_completed_count() const {
    return completed_count;
}

int DownloadProgress::get_total_count() const {
    return total_pieces;
}