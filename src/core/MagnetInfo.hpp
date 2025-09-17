#pragma once
#include <string>

struct MagnetInfo {
    std::string info_hash_hex;
    std::string info_hash_raw;
    std::string tracker_url;
    std::string display_name;
    
    void print_info() const;
};