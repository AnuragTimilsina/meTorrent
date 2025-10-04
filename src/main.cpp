#include "commands/CommandHandler.hpp"
#include <iostream>
#include <vector>

int main(int argc, char* argv[]) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command> <args>" << std::endl;
        std::cerr << "\nAvailable commands:" << std::endl;
        std::cerr << "  Basic:" << std::endl;
        std::cerr << "    decode <encoded_value>" << std::endl;
        std::cerr << "    info <file.torrent>" << std::endl;
        std::cerr << "    peers <file.torrent>" << std::endl;
        std::cerr << "    handshake <file.torrent> <ip:port>" << std::endl;
        std::cerr << "\n  Download:" << std::endl;
        std::cerr << "    download_piece -o <output> <file.torrent> <piece_index>" << std::endl;
        std::cerr << "    download -o <output> <file.torrent> [--single-peer]" << std::endl;
        std::cerr << "\n  Magnet Links:" << std::endl;
        std::cerr << "    magnet_parse <magnet_link>" << std::endl;
        std::cerr << "    magnet_handshake <magnet_link>" << std::endl;
        std::cerr << "    magnet_info <magnet_link>" << std::endl;
        std::cerr << "    magnet_download_piece -o <output> <magnet_link> <piece_index>" << std::endl;
        std::cerr << "    magnet_download -o <output> <magnet_link>" << std::endl;
        return 1;
    }
    
    std::string command = argv[1];
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    
    return CommandHandler::execute(command, args);
}