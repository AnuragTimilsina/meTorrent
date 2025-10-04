#include "CommandHandler.hpp"
#include "helpers/MagnetHelpers.hpp"
#include "helpers/Config.hpp"
#include "../core/BitTorrentClient.hpp"
#include "../core/TorrentInfo.hpp"
#include "../core/Peer.hpp"
#include "../core/MagnetInfo.hpp"
#include "../network/TrackerClient.hpp"
#include "../network/PeerConnection.hpp"
#include "../download/DownloadProgress.hpp"
#include "../download/PieceDownloader.hpp"
#include "../download/WorkQueue.hpp"
#include "../utils/BencodeParser.hpp"
#include "../utils/CryptoUtils.hpp"

#include <iostream>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cerrno>
#include <cstring>

// ============================================================================
// COMMAND EXECUTOR
// ============================================================================

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
    } else if (command == "magnet_parse") {
        handle_magnet_parse(args);
    } else if (command == "magnet_handshake") {
        handle_magnet_handshake(args);
    } else if (command == "magnet_info") {
        handle_magnet_info(args);
    } else if (command == "magnet_download_piece") {
        handle_magnet_download_piece(args);
    } else if (command == "magnet_download") {
        handle_magnet_download(args);
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }
    return 0;
}

// ============================================================================
// BASIC COMMANDS
// ============================================================================

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

// ============================================================================
// DOWNLOAD COMMANDS
// ============================================================================

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
            int num_workers = std::min(Config::DEFAULT_WORKERS, 
                                      static_cast<int>(std::thread::hardware_concurrency()));
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

// ============================================================================
// MAGNET LINK COMMANDS
// ============================================================================

void CommandHandler::handle_magnet_parse(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: magnet_parse <magnet_link>" << std::endl;
        return;
    }

    try {
        MagnetInfo magnet_info = BitTorrentClient::parse_magnet_link(args[0]);
        magnet_info.print_info();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;        
    }
}

void CommandHandler::handle_magnet_handshake(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: magnet_handshake <magnet_link>" << std::endl;
        return;
    }

    try {
        MagnetInfo magnet_info = BitTorrentClient::parse_magnet_link(args[0]);
        auto peers = TrackerClient::get_peers(magnet_info);
        
        if (peers.empty()) {
            std::cerr << "No peers received from tracker." << std::endl;
            return;
        }

        Peer peer = peers[0];
        std::string peer_id = BitTorrentClient::generate_peer_id();

        int sock = PeerConnection::connect_to_peer(peer);
        if (sock < 0) {
            std::cerr << "Failed to connect to peer." << std::endl;
            return;
        }

        std::array<char, 68> handshake_response{};
        if (!PeerConnection::perform_handshake(sock, magnet_info.info_hash_raw, 
                                               peer_id, handshake_response)) {
            std::cerr << "Handshake failed with peer." << std::endl;
            close(sock);
            return;
        }

        std::string remote_peer_id = PeerConnection::extract_peer_id_from_handshake(
            handshake_response.data());
        std::cout << "Peer ID: " << remote_peer_id << std::endl;

        // Read first message (likely bitfield)
        try {
            uint8_t msg_id = 0;
            PeerConnection::recv_message(sock, msg_id);
        } catch (const std::exception& e) {
            // Silently handle
        }

        // Check extension protocol support
        bool peer_supports_extensions = false;
        if (handshake_response.size() >= Config::HANDSHAKE_RESPONSE_SIZE) {
            unsigned char reserved5 = static_cast<unsigned char>(
                handshake_response[Config::EXTENSION_RESERVED_BYTE]);
            peer_supports_extensions = (reserved5 & Config::EXTENSION_BIT) != 0;
        }

        if (peer_supports_extensions) {
            json ext_dict;
            ext_dict["m"] = {{"ut_metadata", 1}};
            std::string bencoded = BencodeParser::json_to_bencode(ext_dict);
            
            std::vector<uint8_t> ext_payload;
            ext_payload.push_back(Config::EXTENSION_HANDSHAKE_ID);
            ext_payload.insert(ext_payload.end(), bencoded.begin(), bencoded.end());

            PeerConnection::send_message(sock, Config::EXTENSION_MESSAGE_ID, ext_payload);

            try {
                uint8_t resp_msg_id = 0;
                std::vector<uint8_t> resp_payload = PeerConnection::recv_message(sock, resp_msg_id);

                if (resp_msg_id == Config::EXTENSION_MESSAGE_ID && 
                    !resp_payload.empty() && 
                    resp_payload[0] == Config::EXTENSION_HANDSHAKE_ID) {
                    
                    std::string benc_str(reinterpret_cast<char*>(resp_payload.data() + 1), 
                                        resp_payload.size() - 1);
                    try {
                        json peer_ext_dict = BencodeParser::decode_bencoded_value(benc_str);

                        if (peer_ext_dict.contains("m") &&
                            peer_ext_dict["m"].is_object() &&
                            peer_ext_dict["m"].contains("ut_metadata")) {
                            int ut_metadata_id = peer_ext_dict["m"]["ut_metadata"].get<int>();
                            std::cout << "Peer Metadata Extension ID: " << ut_metadata_id << std::endl;
                        }
                    } catch (const std::exception& e) {
                        // Silently handle
                    }
                }
            } catch (const std::exception& e) {
                // Silently handle
            }
        }

        close(sock);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void CommandHandler::handle_magnet_info(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: magnet_info <magnet_link>" << std::endl;
        return;
    }

    try {
        MagnetInfo magnet_info = BitTorrentClient::parse_magnet_link(args[0]);
        auto peers = TrackerClient::get_peers(magnet_info);
        
        if (peers.empty()) {
            std::cerr << "No peers received from tracker." << std::endl;
            return;
        }

        TorrentInfo torrent_info;
        if (!MagnetHelpers::retrieve_metadata_from_magnet(magnet_info, peers, torrent_info)) {
            std::cerr << "Failed to retrieve metadata from any peer." << std::endl;
            return;
        }

        MagnetHelpers::print_metadata_info(magnet_info, torrent_info.info_dict);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void CommandHandler::handle_magnet_download_piece(const std::vector<std::string>& args) {
    if (args.size() < 4 || args[0] != "-o") {
        std::cerr << "Usage: magnet_download_piece -o <output_file> <magnet_link> <piece_index>" 
                  << std::endl;
        return;
    }

    std::string output_file = args[1];
    std::string magnet_link = args[2];
    int piece_index = std::stoi(args[3]);

    try {
        MagnetInfo magnet_info = BitTorrentClient::parse_magnet_link(magnet_link);
        auto peers = TrackerClient::get_peers(magnet_info);
        
        if (peers.empty()) {
            std::cerr << "No peers received from tracker." << std::endl;
            return;
        }

        TorrentInfo torrent_info;
        if (!MagnetHelpers::retrieve_metadata_from_magnet(magnet_info, peers, torrent_info)) {
            std::cerr << "Failed to retrieve metadata from any peer." << std::endl;
            return;
        }

        if (!MagnetHelpers::download_single_piece(torrent_info, peers, piece_index, output_file)) {
            std::cerr << "Failed to download piece from any available peer." << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void CommandHandler::handle_magnet_download(const std::vector<std::string>& args) {
    if (args.size() < 3 || args[0] != "-o") {
        std::cerr << "Usage: magnet_download -o <output_file> <magnet_link>" << std::endl;
        return;
    }

    std::string output_file = args[1];
    std::string magnet_link = args[2];

    try {
        MagnetInfo magnet_info = BitTorrentClient::parse_magnet_link(magnet_link);
        auto peers = TrackerClient::get_peers(magnet_info);
        
        if (peers.empty()) {
            std::cerr << "No peers received from tracker." << std::endl;
            return;
        }

        std::cout << "Found " << peers.size() << " peers from tracker" << std::endl;

        TorrentInfo torrent_info;
        if (!MagnetHelpers::retrieve_metadata_from_magnet(magnet_info, peers, torrent_info)) {
            std::cerr << "Failed to retrieve metadata from any peer." << std::endl;
            return;
        }

        std::cout << "Metadata retrieved successfully!" << std::endl;
        std::cout << "File length: " << torrent_info.length << " bytes" << std::endl;
        std::cout << "Piece length: " << torrent_info.piece_length << " bytes" << std::endl;
        std::cout << "Total pieces: " << torrent_info.get_piece_count() << std::endl;

        auto start_time = std::chrono::steady_clock::now();
        
        int num_workers = std::min(Config::DEFAULT_WORKERS, 
                                  static_cast<int>(std::thread::hardware_concurrency()));
        std::cout << "Starting download with " << num_workers << " workers" << std::endl;

        BitTorrentClient::download_file_multi_peer(torrent_info, output_file, num_workers);

        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

        double speed_mbps = (torrent_info.length / (1024.0 * 1024.0)) /
                            std::max(1, static_cast<int>(duration.count()));
        
        std::cout << "Download completed in " << duration.count() << " seconds" << std::endl;
        std::cout << "Average speed: " << std::fixed << std::setprecision(2)
                  << speed_mbps << " MB/s" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Download failed: " << e.what() << std::endl;
    }
}