#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <cstdint>

namespace Config {
    // Worker configuration
    constexpr int DEFAULT_WORKERS = 6;
    
    // Extension protocol constants
    constexpr int EXTENSION_MESSAGE_ID = 20;
    constexpr int EXTENSION_HANDSHAKE_ID = 0;
    constexpr uint8_t EXTENSION_BIT = 0x10;
    constexpr int EXTENSION_RESERVED_BYTE = 25;
    
    // Metadata constants
    constexpr int METADATA_PIECE_INDEX = 0;
    constexpr int METADATA_REQUEST_TYPE = 0;
    constexpr int METADATA_DATA_TYPE = 1;
    constexpr int METADATA_REJECT_TYPE = 2;
    
    // Handshake constants
    constexpr int HANDSHAKE_RESPONSE_SIZE = 68;
}

#endif // CONFIG_HPP