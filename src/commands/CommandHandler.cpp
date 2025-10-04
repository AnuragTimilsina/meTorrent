#include "CommandHandler.hpp"
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

// Add these headers for socket functions
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cerrno>
#include <cstring>

// Execute command driver
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
    }
    
    else {
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
        // Parse the magnet link
        MagnetInfo magnet_info = BitTorrentClient::parse_magnet_link(args[0]);

        // Get peers from tracker
        auto peers = TrackerClient::get_peers(magnet_info);
        if (peers.empty()) {
            std::cerr << "No peers received from tracker." << std::endl;
            return;
        }

        // Pick first peer for testing
        Peer peer = peers[0];

        // Generate local peer ID
        std::string peer_id = BitTorrentClient::generate_peer_id();

        // Connect to peer
        int sock = PeerConnection::connect_to_peer(peer);
        if (sock < 0) {
            std::cerr << "Failed to connect to peer." << std::endl;
            return;
        }

        // Perform handshake
        std::array<char, 68> handshake_response{};
        if (!PeerConnection::perform_handshake(sock, magnet_info.info_hash_raw, peer_id, handshake_response)) {
            std::cerr << "Handshake failed with peer." << std::endl;
            close(sock);
            return;
        }

        // Extract remote peer ID
        std::string remote_peer_id = PeerConnection::extract_peer_id_from_handshake(handshake_response.data());
        std::cout << "Peer ID: " << remote_peer_id << std::endl;

        // Read the first message (likely bitfield)
        try {
            uint8_t msg_id = 0;
            std::vector<uint8_t> msg_payload = PeerConnection::recv_message(sock, msg_id);
            // Don't print bitfield message info for cleaner output
        } catch (const std::exception& e) {
            std::cerr << "Error receiving message: " << e.what() << std::endl;
        }

        // Check if peer supports extension protocol
        bool peer_supports_extensions = false;
        if (handshake_response.size() >= 68) {
            unsigned char reserved5 = static_cast<unsigned char>(handshake_response[25]);
            peer_supports_extensions = (reserved5 & 0x10) != 0;
        }

        if (peer_supports_extensions) {
            // Build extension-handshake payload using JSON -> bencode
            json ext_dict;
            ext_dict["m"] = { {"ut_metadata", 1} }; // advertise ut_metadata support

            std::string bencoded = BencodeParser::json_to_bencode(ext_dict);
            std::vector<uint8_t> ext_payload;
            ext_payload.push_back(0); // extension handshake ID
            ext_payload.insert(ext_payload.end(), bencoded.begin(), bencoded.end());

            // Send extension-handshake (message ID = 20)
            PeerConnection::send_message(sock, 20, ext_payload);

            // Receive peer's extension-handshake back
            try {
                uint8_t resp_msg_id = 0;
                std::vector<uint8_t> resp_payload = PeerConnection::recv_message(sock, resp_msg_id);

                if (resp_msg_id == 20 && !resp_payload.empty() && resp_payload[0] == 0) {
                    // Decode bencoded payload
                    std::string benc_str(reinterpret_cast<char*>(resp_payload.data() + 1), resp_payload.size() - 1);
                    try {
                        json peer_ext_dict = BencodeParser::decode_bencoded_value(benc_str);

                        if (peer_ext_dict.contains("m") &&
                            peer_ext_dict["m"].is_object() &&
                            peer_ext_dict["m"].contains("ut_metadata")) {
                                int ut_metadata_id = peer_ext_dict["m"]["ut_metadata"].get<int>();
                                std::cout << "Peer Metadata Extension ID: " << ut_metadata_id << std::endl;
                        }
                    } catch (const std::exception& e) {
                        // Silently handle parsing errors - just don't print the metadata extension ID
                    }
                }
            } catch (const std::exception& e) {
                // Silently handle receive errors - just don't print the metadata extension ID
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

        Peer peer = peers[0];
        std::string peer_id = BitTorrentClient::generate_peer_id();

        int sock = PeerConnection::connect_to_peer(peer);
        if (sock < 0) {
            std::cerr << "Failed to connect to peer." << std::endl;
            return;
        }

        std::array<char, 68> handshake_response{};
        if (!PeerConnection::perform_handshake(sock, magnet_info.info_hash_raw, peer_id, handshake_response)) {
            std::cerr << "Handshake failed with peer." << std::endl;
            close(sock);
            return;
        }

        // Try to read first peer message (bitfield, keepalive, etc.)
        try {
            uint8_t msg_id = 0;
            PeerConnection::recv_message(sock, msg_id);
        } catch (...) {
            // Not critical, continue
        }

        bool peer_supports_extensions = false;
        if (handshake_response.size() >= 68) {
            unsigned char reserved5 = static_cast<unsigned char>(handshake_response[25]);
            peer_supports_extensions = (reserved5 & 0x10) != 0;
        }
        if (!peer_supports_extensions) {
            std::cerr << "Peer does not support extension protocol." << std::endl;
            close(sock);
            return;
        }

        // Send extension handshake
        json ext_dict;
        ext_dict["m"] = { {"ut_metadata", 1} };
        std::string bencoded = BencodeParser::json_to_bencode(ext_dict);

        std::vector<uint8_t> ext_payload;
        ext_payload.push_back(0); // extended message id = 0 (handshake)
        ext_payload.insert(ext_payload.end(), bencoded.begin(), bencoded.end());
        PeerConnection::send_message(sock, 20, ext_payload);

        // Receive extension handshake
        uint8_t peer_ut_metadata_id = 0;
        {
            uint8_t resp_msg_id = 0;
            auto resp_payload = PeerConnection::recv_message(sock, resp_msg_id);

            if (resp_msg_id == 20 && !resp_payload.empty() && resp_payload[0] == 0) {
                std::string benc_str(reinterpret_cast<char*>(resp_payload.data() + 1),
                                     resp_payload.size() - 1);
                json peer_ext_dict = BencodeParser::decode_bencoded_value(benc_str);

                if (peer_ext_dict.contains("m") &&
                    peer_ext_dict["m"].is_object() &&
                    peer_ext_dict["m"].contains("ut_metadata")) {
                    peer_ut_metadata_id = peer_ext_dict["m"]["ut_metadata"].get<int>();
                } else {
                    std::cerr << "Peer does not support ut_metadata extension." << std::endl;
                    close(sock);
                    return;
                }
            } else {
                std::cerr << "Invalid extension handshake response." << std::endl;
                close(sock);
                return;
            }
        }

        // Request metadata piece 0
        json request_dict;
        request_dict["msg_type"] = 0;
        request_dict["piece"] = 0;

        std::string bencoded_request = BencodeParser::json_to_bencode(request_dict);
        std::vector<uint8_t> request_payload;
        request_payload.push_back(peer_ut_metadata_id);
        request_payload.insert(request_payload.end(),
                               bencoded_request.begin(),
                               bencoded_request.end());

        PeerConnection::send_message(sock, 20, request_payload);

        // Receive metadata response
        uint8_t metadata_msg_id = 0;
        auto metadata_payload = PeerConnection::recv_message(sock, metadata_msg_id);

        if (metadata_msg_id != 20 || metadata_payload.empty()) {
            std::cerr << "Invalid metadata response." << std::endl;
            close(sock);
            return;
        }

        std::string full_payload(reinterpret_cast<char*>(metadata_payload.data() + 1),
                                 metadata_payload.size() - 1);

        // Split dictionary and metadata
        size_t pos = 0;
        json metadata_dict = BencodeParser::decode_bencoded_value(full_payload, pos);

        if (!metadata_dict.contains("msg_type") || metadata_dict["msg_type"].get<int>() != 1) {
            std::cerr << "Expected metadata data message (msg_type=1)." << std::endl;
            close(sock);
            return;
        }

        std::string metadata_content = full_payload.substr(pos);

        // Parse metadata dictionary (the "info" dict)
        json info_dict = BencodeParser::decode_bencoded_value(metadata_content);

        // Validate SHA1(info) == info_hash
        std::string reencoded_info = BencodeParser::json_to_bencode(info_dict);
        std::string computed_hash = CryptoUtils::sha1_to_hex(reencoded_info);

        if (computed_hash != magnet_info.info_hash_hex) {
            std::cerr << "Metadata hash validation failed!" << std::endl;
            close(sock);
            return;
        }

        // Output results
        std::cout << "Tracker URL: " << magnet_info.tracker_url << std::endl;
        if (info_dict.contains("length"))
            std::cout << "Length: " << info_dict["length"].get<int64_t>() << std::endl;
        std::cout << "Info Hash: " << magnet_info.info_hash_hex << std::endl;
        if (info_dict.contains("piece length"))
            std::cout << "Piece Length: " << info_dict["piece length"].get<int>() << std::endl;

        if (info_dict.contains("pieces")) {
            std::cout << "Piece Hashes:" << std::endl;
            std::string pieces_raw = info_dict["pieces"].get<std::string>();
            for (size_t i = 0; i < pieces_raw.size(); i += 20) {
                std::string piece_hash_hex;
                for (int j = 0; j < 20 && (i + j) < pieces_raw.size(); ++j) {
                    char hex_byte[3];
                    sprintf(hex_byte, "%02x", static_cast<unsigned char>(pieces_raw[i + j]));
                    piece_hash_hex += hex_byte;
                }
                std::cout << piece_hash_hex << std::endl;
            }
        }

        close(sock);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}










