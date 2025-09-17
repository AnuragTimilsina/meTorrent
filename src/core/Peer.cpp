#include "Peer.hpp"

Peer::Peer(const std::string& ip, uint16_t port) : ip(ip), port(port) {}

std::string Peer::to_string() const {
    return ip + ":" + std::to_string(port);
}