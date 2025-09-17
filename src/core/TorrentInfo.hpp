#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include "../lib/nlohmann/json.hpp"

using json = nlohmann::json;

class TorrentInfo {
public:
    std::string tracker_url;
    int64_t length;
    int piece_length;
    std::string info_hash_hex;
    std::string info_hash_raw;
    std::vector<std::array<uint8_t, 20>> piece_hashes;
    json info_dict;
    
    void print_info() const;
    int get_piece_count() const;
    int get_piece_size(int piece_index) const;
};