#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <curl/curl.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "lib/nlohmann/json.hpp"
using json = nlohmann::json;
using decoded = std::pair<json, size_t>;

// Helper functions
std::string binToHex(const std::string& bin) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : bin) {
        ss << std::setw(2) << static_cast<unsigned>(c);
    }
    return ss.str();
}

struct Msg {
    uint32_t length;
    uint8_t id;
} __attribute__((packed));

struct ReqMsg {
    uint32_t length;
    uint8_t id;
    uint32_t index;
    uint32_t begin;
    uint32_t length_block;
} __attribute__((packed));

struct info {
    std::string url;
    size_t length;
    std::string hash;
    size_t pLen;
    std::vector<std::string> pHash;
    
    void printInfo() const {
        std::cout << "Tracker URL: " << url << "\n"
                  << "Length: " << length << "\n"
                  << "Info Hash: " << binToHex(hash) << "\n"
                  << "Piece Length: " << pLen << "\n"
                  << "Piece Hashes:\n";
        for (const auto& h : pHash) {
            std::cout << binToHex(h) << "\n";
        }
    }
};

// Bencode decoding
decoded decode_bencoded_value(const std::string& encoded_value);

decoded decode_bencoded_str(const std::string& str) {
    size_t colon = str.find(':');
    if (colon != std::string::npos) {
        int64_t number = std::stoll(str.substr(0, colon));
        return {json(str.substr(colon+1, number)), colon+number+1};
    }
    throw std::runtime_error("Invalid string encoding");
}

decoded decode_bencoded_int(const std::string& encoded_value) {
    size_t pos = encoded_value.find('e');
    if (pos != std::string::npos) {
        return {json(std::stoll(encoded_value.substr(1, pos-1))), pos+1};
    }
    throw std::runtime_error("Invalid integer encoding");
}

decoded decode_bencoded_list(const std::string& encoded_value) {
    json arr = json::array();
    size_t index = 1;
    while (encoded_value[index] != 'e') {
        auto [value, length] = decode_bencoded_value(encoded_value.substr(index));
        arr.push_back(value);
        index += length;
    }
    return {arr, index+1};
}

decoded decode_bencoded_dict(const std::string& encoded_value) {
    json obj = json::object();
    size_t index = 1;
    while (encoded_value[index] != 'e') {
        auto [key, key_length] = decode_bencoded_str(encoded_value.substr(index));
        index += key_length;
        auto [value, value_length] = decode_bencoded_value(encoded_value.substr(index));
        index += value_length;
        obj[key.get<std::string>()] = value;
    }
    return {obj, index+1};
}

decoded decode_bencoded_value(const std::string& encoded_value) {
    if (encoded_value.empty()) return {json(), 0};
    switch (encoded_value[0]) {
        case 'i': return decode_bencoded_int(encoded_value);
        case 'l': return decode_bencoded_list(encoded_value);
        case 'd': return decode_bencoded_dict(encoded_value);
        default:  return decode_bencoded_str(encoded_value);
    }
}

// Torrent processing
info decode_bencoded_info(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    json root = decode_bencoded_value(content).first;
    
    info result;
    result.url = root["announce"];
    json info_dict = root["info"];
    
    std::ostringstream bencoded_info;
    bencoded_info << 'd';
    for (auto& [key, value] : info_dict.items()) {
        bencoded_info << key.size() << ':' << key;
        if (value.is_number()) {
            bencoded_info << 'i' << value.dump() << 'e';
        } else {
            bencoded_info << value.get<std::string>().size() << ':' << value.get<std::string>();
        }
    }
    bencoded_info << 'e';
    
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(bencoded_info.str().data()), bencoded_info.str().size(), hash);
    result.hash = std::string(reinterpret_cast<char*>(hash), SHA_DIGEST_LENGTH);
    
    result.length = info_dict["length"];
    result.pLen = info_dict["piece length"];
    std::string pieces = info_dict["pieces"];
    for (size_t i = 0; i < pieces.size(); i += 20) {
        result.pHash.push_back(pieces.substr(i, 20));
    }
    return result;
}

// Networking
std::string urlEncode(const std::string& url) {
    char* encoded = curl_easy_escape(nullptr, url.c_str(), url.size());
    std::string result(encoded);
    curl_free(encoded);
    return result;
}

std::string constructTrackerURL(const info& metadata, const std::string& peer_id, int port) {
    std::ostringstream oss;
    oss << metadata.url << "?info_hash=" << urlEncode(metadata.hash)
        << "&peer_id=" << peer_id
        << "&port=" << port
        << "&uploaded=0&downloaded=0&left=" << metadata.length
        << "&compact=1";
    return oss.str();
}

std::vector<std::string> getPeers(const std::string& tracker_url) {
    CURL* curl = curl_easy_init();
    std::vector<char> buffer;
    
    curl_easy_setopt(curl, CURLOPT_URL, tracker_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void* ptr, size_t size, size_t nmemb, std::vector<char>* buf) {
        buf->insert(buf->end(), (char*)ptr, (char*)ptr + size*nmemb);
        return size*nmemb;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        throw std::runtime_error("Tracker request failed");
    }
    
    json response = decode_bencoded_value(std::string(buffer.begin(), buffer.end())).first;
    std::vector<std::string> peers;
    
    for (size_t i = 0; i < response["peers"].get<std::string>().size(); i += 6) {
        const std::string& data = response["peers"];
        std::string ip = std::to_string((uint8_t)data[i]) + "." 
                       + std::to_string((uint8_t)data[i+1]) + "."
                       + std::to_string((uint8_t)data[i+2]) + "."
                       + std::to_string((uint8_t)data[i+3]);
        uint16_t port = (uint8_t)data[i+4] << 8 | (uint8_t)data[i+5];
        peers.push_back(ip + ":" + std::to_string(port));
    }
    
    curl_easy_cleanup(curl);
    return peers;
}

int connectToPeer(const std::string& address, const std::string& info_hash) {
    size_t colon = address.find(':');
    std::string ip = address.substr(0, colon);
    int port = std::stoi(address.substr(colon+1));
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);
    
    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        return -1;
    }
    
    std::vector<char> handshake;
    handshake.push_back(19);
    handshake.insert(handshake.end(), "BitTorrent protocol", "BitTorrent protocol"+19);
    handshake.insert(handshake.end(), 8, 0);
    handshake.insert(handshake.end(), info_hash.begin(), info_hash.end());
    handshake.insert(handshake.end(), "00112233445566778899", "00112233445566778899"+20);
    
    send(sock, handshake.data(), handshake.size(), 0);
    
    char response[68];
    recv(sock, response, 68, 0);
    
    return sock;
}

// Core download logic
void downloadPiece(int sock, int piece_index, size_t piece_length, const std::string& expected_hash, std::ostream& output) {
    send(sock, "\0\0\0\x01\x02", 5, 0); // Interested
    
    char unchoke[5];
    recv(sock, unchoke, 5, 0);
    
    const size_t BLOCK_SIZE = 16384;
    std::string piece_data;
    
    for (size_t offset = 0; offset < piece_length; offset += BLOCK_SIZE) {
        size_t request_size = std::min(BLOCK_SIZE, piece_length - offset);
        
        ReqMsg request{htonl(13), 6, htonl(piece_index), htonl(offset), htonl(request_size)};
        send(sock, &request, sizeof(request), 0);
        
        char header[5];
        recv(sock, header, 4, MSG_WAITALL);
        uint32_t length = ntohl(*(uint32_t*)header);
        
        std::vector<char> buffer(length);
        recv(sock, buffer.data(), length, MSG_WAITALL);
        
        piece_data.append(buffer.begin() + 9, buffer.end());
    }
    
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(piece_data.data()), piece_data.size(), hash);
    if (std::string(reinterpret_cast<char*>(hash), SHA_DIGEST_LENGTH) != expected_hash) {
        throw std::runtime_error("Piece hash mismatch");
    }
    
    output.write(piece_data.data(), piece_data.size());
}

// Command implementations
void handleDownloadPiece(const std::string& torrent_file, int piece_index, const std::string& output_file) {
    info metadata = decode_bencoded_info(torrent_file);
    std::vector<std::string> peers = getPeers(constructTrackerURL(metadata, "00112233445566778899", 6881));
    
    for (const auto& peer : peers) {
        int sock = connectToPeer(peer, metadata.hash);
        if (sock == -1) continue;
        
        std::ofstream out(output_file, std::ios::binary);
        try {
            downloadPiece(sock, piece_index, 
                         (piece_index == metadata.pHash.size()-1) 
                            ? metadata.length % metadata.pLen 
                            : metadata.pLen,
                         metadata.pHash[piece_index], out);
            close(sock);
            return;
        } catch (...) {
            close(sock);
        }
    }
    throw std::runtime_error("Failed to download piece from all peers");
}

void handleDownload(const std::string& torrent_file, const std::string& output_file) {
    info metadata = decode_bencoded_info(torrent_file);
    std::vector<std::string> peers = getPeers(constructTrackerURL(metadata, "00112233445566778899", 6881));
    
    std::ofstream out(output_file, std::ios::binary);
    for (const auto& peer : peers) {
        int sock = connectToPeer(peer, metadata.hash);
        if (sock == -1) continue;
        
        try {
            for (size_t i = 0; i < metadata.pHash.size(); i++) {
                downloadPiece(sock, i, 
                            (i == metadata.pHash.size()-1) 
                                ? metadata.length % metadata.pLen 
                                : metadata.pLen,
                            metadata.pHash[i], out);
            }
            close(sock);
            return;
        } catch (...) {
            close(sock);
        }
    }
    throw std::runtime_error("Failed to download file from all peers");
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <command> [options]\n";
            return 1;
        }
        
        std::string command = argv[1];
        if (command == "decode") {
            // Decode command implementation
        }
        else if (command == "info") {
            info metadata = decode_bencoded_info(argv[2]);
            metadata.printInfo();
        }
        else if (command == "peers") {
            info metadata = decode_bencoded_info(argv[2]);
            for (const auto& peer : getPeers(constructTrackerURL(metadata, "00112233445566778899", 6881))) {
                std::cout << peer << "\n";
            }
        }
        else if (command == "download_piece" && argc == 6) {
            handleDownloadPiece(argv[4], std::stoi(argv[5]), argv[3]);
        }
        else if (command == "download" && argc == 5) {
            handleDownload(argv[4], argv[3]);
        }
        else {
            std::cerr << "Invalid command or arguments\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}