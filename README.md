# BitTorrent Client (C++ Implementation)

A clean, standards-compliant BitTorrent client implementation focusing on core protocol mechanics and reliability.

##  Features

###  Core Implementation
- **Bencoding Support**: Full parser for strings, integers, lists, and dictionaries.
- **Tracker Communication**: HTTP tracker integration with proper URL encoding.
- **Peer Protocol**:
  - Handshake negotiation
  - Choke/Unchoke mechanism
  - Piece selection (rarest-first strategy)
  - Block requests (16KB chunks per request)
- **Validation**: Ensures data integrity via SHA-1 hash verification.


##  Technical Stack

- **Language**: C++17
- **Libraries**:
  - `libcurl` (HTTP requests for tracker communication)
  - `OpenSSL` (SHA-1 hashing for data verification)
  - `nlohmann/json` (configuration management)
- **Build System**: CMake

---

##  Implementation Details

### 🔹 Key Components
- **Bencode Parser**: Recursive descent parser with strict validation.
- **Peer Manager**: Handles multiple TCP connections with timeout handling.
- **Piece Assembler**: Manages partial blocks and verifies integrity via hash checks.
- **Request Scheduler**: Implements request pipelining for efficient downloads.

###  Performance Considerations
- **Memory-mapped file I/O**: Efficient handling of large downloads.
- **Connection reuse**: Reduces overhead for tracker requests.
- **Zero-copy buffer management**: Optimizes data transfer between peers.

###  Limitations
- **Single-threaded downloader**: No parallel piece requests yet. Coming soon! 
- **Basic choking algorithm**: Needs optimization for better peer interaction.
- **Magnet URI limitations**: Requires full hash disclosure to function properly. 

---

##  Future Improvements
- Multi-threaded downloading for better performance.
- Improved choking algorithm for better peer selection.
- Fully functional Magnet URI resolution.
- Enhanced peer discovery mechanisms.

---

