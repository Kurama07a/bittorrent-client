# BitTorrent Client (C++ Implementation)

A standards-compliant single-threaded BitTorrent client implementation focusing on core protocol mechanics.

## Features

- **Bencoding Support**: Parser for strings, integers, lists, and dictionaries.
- **Tracker Communication**: HTTP tracker integration with URL encoding.
- **Peer Protocol**:
  - Handshake negotiation
  - Choke/Unchoke mechanism
  - Sequential piece download
  - Block requests (16KB chunks per request)
- **Validation**: Data integrity via SHA-1 hash verification.

## Technical Stack

- **Language**: C++23
- **Libraries**:
  - `libcurl` (HTTP requests)
  - `OpenSSL` (SHA-1 hashing)
  - `nlohmann/json` (JSON parsing)
- **Build System**: CMake

---

## Implementation Details

### Key Components
- **Bencode Parser**: Recursive descent parser with strict validation.
- **Peer Communication**: Manages TCP connections and message exchanges.
- **Piece Assembler**: Handles block buffering and verifies integrity via SHA-1.
- **Request Handling**: Issues block requests in 16KB chunks per piece.

### Limitations
- Single-threaded downloader; no parallel piece requests.
- Basic choking algorithm without advanced selection.
- Does not support Magnet URIs.

---

## CLI Usage

```sh
# Build
cmake -B build -S .
cmake --build build

# Commands
./build/bittorrent decode <encoded_value>
./build/bittorrent info <torrent_file>
./build/bittorrent peers <torrent_file>
./build/bittorrent handshake <torrent_file> <peer_ip>:<port>
./build/bittorrent download_piece -o <output_path> <torrent_file> <piece_index>
./build/bittorrent download -o <output_path> <torrent_file>
```

---

## Future Improvements

- Multi-threaded downloading
- Advanced choking algorithms
- Full Magnet URI support
- Enhanced peer discovery
