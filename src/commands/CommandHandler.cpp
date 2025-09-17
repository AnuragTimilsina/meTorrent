#include "CommandHandler.hpp"
#include "../core/BitTorrentClient.hpp"
#include "../core/TorrentInfo.hpp"
#include "../core/Peer.hpp"
#include "../network/TrackerClient.hpp"
#include "../network/PeerConnection.hpp"
#include "../download/DownloadProgress.hpp"
#include "../download/PieceDownloader.hpp"
#include "../download/WorkQueue.hpp"
#include "../utils/BencodeParser.hpp"

#include <iostream>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <thread>

// Add these headers for socket functions
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cerrno>
#include <cstring>


int CommandHandler::execute(const std::string& command, const std::vector<std::string>& args) {
    if (command == "decode") {
        handle_decode(args);
    } else if (command == "info") {
        handle_info(args);
    } else if (command == "peers") {
        handle_peers(args);
    } else if (command == "handshake") {
        handle_handshake(args);
    } else if (command == "download_piece") {
        handle_download_piece(args);
    } else if (command == "download") {
        handle_download(args);
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }
    return 0;
}

void CommandHandler::handle_decode(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: decode <encoded_value>" << std::endl;
        return;
    }
    auto decoded = BencodeParser::decode_bencoded_value(args[0]);
    std::cout << decoded.dump() << std::endl;
}

void CommandHandler::handle_info(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: info <file.torrent>" << std::endl;
        return;
    }
    TorrentInfo info = BitTorrentClient::parse_torrent(args[0]);
    info.print_info();
}

void CommandHandler::handle_peers(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: peers <file.torrent>" << std::endl;
        return;
    }
    TorrentInfo info = BitTorrentClient::parse_torrent(args[0]);
    auto peers = TrackerClient::get_peers(info);
    for (auto& peer : peers) {
        std::cout << peer.to_string() << std::endl;
    }
}

void CommandHandler::handle_handshake(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "Usage: handshake <file.torrent> <ip:port>" << std::endl;
        return;
    }

    try {
        TorrentInfo info = BitTorrentClient::parse_torrent(args[0]);

        // Parse peer address
        std::string peer_addr = args[1];
        size_t colon_pos = peer_addr.find(":");
        if (colon_pos == std::string::npos) {
            std::cerr << "Invalid peer address format. Use <ip>:<port>." << std::endl;
            return;
        }

        std::string ip = peer_addr.substr(0, colon_pos);
        int port = std::stoi(peer_addr.substr(colon_pos + 1));
        Peer peer(ip, port);

        std::string peer_id = BitTorrentClient::generate_peer_id();
        int sock = PeerConnection::connect_to_peer(peer);
        if (sock < 0) {
            std::cerr << "Failed to connect to peer." << std::endl;
            return;
        }

        std::array<char, 68> response;
        if (!PeerConnection::perform_handshake(sock, info.info_hash_raw, peer_id, response)) {
            close(sock);
            return;
        }

        close(sock);
        std::string peer_id_hex = PeerConnection::extract_peer_id_from_handshake(response.data());
        std::cout << "Peer ID: " << peer_id_hex << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void CommandHandler::handle_download_piece(const std::vector<std::string>& args) {
    if (args.size() < 4 || args[0] != "-o") {
        std::cerr << "Usage: download_piece -o <output_file> <file.torrent> <piece_index>" << std::endl;
        return;
    }

    std::string output_file = args[1];
    std::string torrent_file = args[2];
    int piece_index = std::stoi(args[3]);

    try {
        TorrentInfo info = BitTorrentClient::parse_torrent(torrent_file);
        auto peers = TrackerClient::get_peers(info);

        if (peers.empty()) {
            std::cerr << "No peers available from tracker." << std::endl;
            return;
        }

        // Try only the first peer for simplicity
        BitTorrentClient::download_piece(info, peers[0], piece_index, output_file);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void CommandHandler::handle_download(const std::vector<std::string>& args) {
    if (args.size() < 3 || args[0] != "-o") {
        std::cerr << "Usage: download -o <output_file> <file.torrent> [--single-peer]" << std::endl;
        return;
    }

    std::string output_file = args[1];
    std::string torrent_file = args[2];
    bool single_peer = (args.size() > 3 && args[3] == "--single-peer");

    try {
        TorrentInfo info = BitTorrentClient::parse_torrent(torrent_file);

        std::cout << "Starting download of " << info.length << " bytes in "
                  << info.get_piece_count() << " pieces" << std::endl;

        auto start_time = std::chrono::steady_clock::now();

        if (single_peer) {
            std::cout << "Using single-peer mode" << std::endl;
            BitTorrentClient::download_file_single_peer(info, output_file);
        } else {
            int num_workers = std::min(6, static_cast<int>(std::thread::hardware_concurrency()));
            std::cout << "Using multi-peer mode with " << num_workers << " workers" << std::endl;
            BitTorrentClient::download_file_multi_peer(info, output_file, num_workers);
        }

        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

        double speed_mbps = (info.length / (1024.0 * 1024.0)) /
                            std::max(1, static_cast<int>(duration.count()));
        std::cout << "Download completed in " << duration.count() << " seconds" << std::endl;
        std::cout << "Average speed: " << std::fixed << std::setprecision(2)
                  << speed_mbps << " MB/s" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Download failed: " << e.what() << std::endl;
    }
}
