#pragma once
#include <string>
#include <cstdint>

struct Peer {
    std::string ip;
    uint16_t port;
    
    Peer(const std::string& ip, uint16_t port);
    std::string to_string() const;
};