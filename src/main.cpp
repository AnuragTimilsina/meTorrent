#include "commands/CommandHandler.hpp"
#include <iostream>
#include <vector>

int main(int argc, char* argv[]) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command> <args>" << std::endl;
        std::cerr << "Commands: decode, info, peers, handshake, download_piece, download, magnet_parse, magnet_handshake, magnet_info" << std::endl;
        return 1;
    }
    
    std::string command = argv[1];
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    
    return CommandHandler::execute(command, args);
}