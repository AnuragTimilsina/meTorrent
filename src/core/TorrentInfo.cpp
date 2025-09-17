#include "TorrentInfo.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

void TorrentInfo::print_info() const {
    std::cout << "Tracker URL: " << tracker_url << std::endl;
    std::cout << "Length: " << length << std::endl;
    std::cout << "Info Hash: " << info_hash_hex << std::endl;
    std::cout << "Piece Length: " << piece_length << std::endl;
    std::cout << "Piece Hashes: " << std::endl;
    
    for (const auto& hash : piece_hashes) {
        std::ostringstream oss;
        for (unsigned char c : hash) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        std::cout << oss.str() << std::endl;
    }
}

int TorrentInfo::get_piece_count() const {
    return static_cast<int>(piece_hashes.size());
}

int TorrentInfo::get_piece_size(int piece_index) const {
    int total_pieces = get_piece_count();
    if (piece_index < total_pieces - 1) {
        return piece_length;
    } else {
        // Last piece might be smaller
        int last_piece_size = length % piece_length;
        return last_piece_size == 0 ? piece_length : last_piece_size;
    }
}