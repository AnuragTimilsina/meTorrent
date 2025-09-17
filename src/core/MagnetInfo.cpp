#include "MagnetInfo.hpp"
#include <iostream>

void MagnetInfo::print_info() const {
    std::cout << "Tracker URL: " << tracker_url << std::endl;
    std::cout << "Info Hash: " << info_hash_hex << std::endl;
    if (!display_name.empty()) {
        std::cout << "Display Name: " << display_name << std::endl;
    }
}