#ifndef MAGNET_HELPERS_HPP
#define MAGNET_HELPERS_HPP

#include "../../core/MagnetInfo.hpp"
#include "../../core/TorrentInfo.hpp"
#include "../../core/Peer.hpp"
#include "../../utils/BencodeParser.hpp"
#include <vector>
#include <string>

namespace MagnetHelpers {

/**
 * Retrieve metadata (info dictionary) from peers using BitTorrent extension protocol
 * @param magnet_info The parsed magnet link information
 * @param peers List of available peers
 * @param torrent_info Output parameter - will be populated with metadata
 * @return true if metadata was successfully retrieved, false otherwise
 */
bool retrieve_metadata_from_magnet(
    const MagnetInfo& magnet_info,
    const std::vector<Peer>& peers,
    TorrentInfo& torrent_info
);

/**
 * Print metadata information in a formatted way
 * @param magnet_info The magnet link information
 * @param info_dict The info dictionary from metadata
 */
void print_metadata_info(
    const MagnetInfo& magnet_info,
    const json& info_dict
);

/**
 * Download a single piece and save to file
 * @param torrent_info Complete torrent metadata
 * @param peers List of available peers
 * @param piece_index Index of piece to download
 * @param output_file Path to output file
 * @return true if piece was successfully downloaded, false otherwise
 */
bool download_single_piece(
    const TorrentInfo& torrent_info,
    const std::vector<Peer>& peers,
    int piece_index,
    const std::string& output_file
);

} // namespace MagnetHelpers

#endif // MAGNET_HELPERS_HPP