#include "TrackerClient.hpp"
#include "../core/BitTorrentClient.hpp"
#include "../utils/NetworkUtils.hpp"
#include "../utils/BencodeParser.hpp"
#include <curl/curl.h>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>

// --- Existing TorrentInfo version ---
std::vector<Peer> TrackerClient::get_peers(const TorrentInfo& torrent_info) {
    std::string peer_id = BitTorrentClient::generate_peer_id();

    std::ostringstream url;
    url << torrent_info.tracker_url
        << "?info_hash=" << NetworkUtils::url_encode(torrent_info.info_hash_raw)
        << "&peer_id=" << NetworkUtils::url_encode(peer_id)
        << "&port=" << 6881
        << "&uploaded=0&downloaded=0"
        << "&left=" << torrent_info.length
        << "&compact=1";

    CURL* curl = curl_easy_init();
    std::string response;

    if (!curl) throw std::runtime_error("Failed to initialize CURL");

    curl_easy_setopt(curl, CURLOPT_URL, url.str().c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
        throw std::runtime_error("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));

    json tracker_response = BencodeParser::decode_bencoded_value(response);

    if (!tracker_response.contains("peers") || !tracker_response["peers"].is_string())
        throw std::runtime_error("Tracker response does not contain valid peers");

    return parse_peers_compact(tracker_response["peers"]);
}

// TrackerClient.cpp — MagnetInfo version
std::vector<Peer> TrackerClient::get_peers(const MagnetInfo& magnet_info) {
    std::string peer_id = BitTorrentClient::generate_peer_id();

    // Temporary fake length to satisfy tracker
    int64_t fake_length = 1024; // 1 KB

    std::ostringstream url;
    url << magnet_info.tracker_url
        << "?info_hash=" << NetworkUtils::url_encode(magnet_info.info_hash_raw)
        << "&peer_id=" << NetworkUtils::url_encode(peer_id)
        << "&port=6881"
        << "&uploaded=0&downloaded=0"
        << "&left=" << fake_length  // non-zero for tracker
        << "&compact=1";

    CURL* curl = curl_easy_init();
    std::string response;

    if (!curl) throw std::runtime_error("Failed to initialize CURL");

    curl_easy_setopt(curl, CURLOPT_URL, url.str().c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
        throw std::runtime_error("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));

    json tracker_response = BencodeParser::decode_bencoded_value(response);

    if (!tracker_response.contains("peers") || !tracker_response["peers"].is_string())
        throw std::runtime_error("Tracker response does not contain valid peers");

    return parse_peers_compact(tracker_response["peers"]);
}

// --- unchanged helpers ---
size_t TrackerClient::write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    std::string* output = static_cast<std::string*>(userp);
    output->append((char*)contents, total_size);
    return total_size;
}

std::vector<Peer> TrackerClient::parse_peers_compact(const std::string& peers_compact) {
    std::vector<Peer> peers;

    for (size_t i = 0; i + 6 <= peers_compact.size(); i += 6) {
        uint8_t ip_bytes[4];
        uint16_t port;

        memcpy(ip_bytes, &peers_compact[i], 4);
        memcpy(&port, &peers_compact[i + 4], 2);

        std::string ip = std::to_string(ip_bytes[0]) + "." +
                         std::to_string(ip_bytes[1]) + "." +
                         std::to_string(ip_bytes[2]) + "." +
                         std::to_string(ip_bytes[3]);

        port = ntohs(port);
        peers.emplace_back(ip, port);
    }

    return peers;
}
