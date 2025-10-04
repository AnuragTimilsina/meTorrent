#pragma once
#include <string>
#include <vector>

class CommandHandler {
public:
    static int execute(const std::string& command, const std::vector<std::string>& args);
    
private:
    static void handle_decode(const std::vector<std::string>& args);
    static void handle_info(const std::vector<std::string>& args);
    static void handle_peers(const std::vector<std::string>& args);
    static void handle_handshake(const std::vector<std::string>& args);
    static void handle_download_piece(const std::vector<std::string>& args);
    static void handle_download(const std::vector<std::string>& args);
    static void handle_magnet_parse(const std::vector<std::string>& args);
    static void handle_magnet_handshake(const std::vector<std::string>& args);
    static void handle_magnet_info(const std::vector<std::string>& args);
    static void handle_magnet_download_piece(const std::vector<std::string>& args);
    static void handle_magnet_download(const std::vector<std::string>& args);
};