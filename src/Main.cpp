#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
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

std::string binToHex(const std::string& bin);
std::string hexToBin(const std::string& hex);

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
        std::cout << "Tracker URL: " << url << "\nLength: " << length 
                  << "\nInfo Hash: " << binToHex(hash) << "\nPiece Length: " << pLen
                  << "\nPiece Hashes:\n";
        for (const auto& h : pHash) std::cout << h << '\n';
    }
};

std::string urlEncode(const std::string& url) {
    char *encoded = curl_easy_escape(nullptr, url.c_str(), url.size());
    std::string res(encoded);
    curl_free(encoded);
    return res;
}

std::string constructTrackerURL(const std::string& trackerUrl, const std::string& inf_hash,
                                const std::string& peerId, int port, int uploaded,
                                int downloaded, int left, int compact) {
    return trackerUrl + "?info_hash=" + urlEncode(inf_hash) + "&peer_id=" + peerId +
           "&port=" + std::to_string(port) + "&uploaded=" + std::to_string(uploaded) +
           "&downloaded=" + std::to_string(downloaded) + "&left=" + std::to_string(left) +
           "&compact=" + std::to_string(compact);
}

std::string sha1(const std::string& inp) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(inp.c_str()), inp.size(), hash);
    return std::string(reinterpret_cast<const char*>(hash), SHA_DIGEST_LENGTH);
}

decoded decode_bencoded_value(const std::string& encoded_value);

decoded decode_bencoded_str(const std::string& str) {
    size_t colon = str.find(':');
    if(colon == std::string::npos) throw std::runtime_error("Invalid encoded string");
    int64_t number = std::stoll(str.substr(0, colon));
    return {str.substr(colon+1, number), colon+1+number};
}

decoded decode_bencoded_int(const std::string& encoded_value) {
    size_t pos = encoded_value.find('e');
    if (pos == std::string::npos) throw std::runtime_error("Invalid integer encoding");
    return {std::stoll(encoded_value.substr(1, pos-1)), pos+1};
}

decoded decode_bencoded_list(const std::string& encode_value) {
    std::string str = encode_value.substr(1);
    json arr = json::array();
    while(str[0] != 'e') {
        auto [val, len] = decode_bencoded_value(str);
        arr.push_back(val);
        str = str.substr(len);
    }
    return {arr, encode_value.size()-str.size()+1};
}

decoded decode_bencoded_dict(const std::string& encode_value) {
    std::string str = encode_value.substr(1);
    json obj = json::object();
    while(str[0] != 'e') {
        auto [key, klen] = decode_bencoded_str(str);
        str = str.substr(klen);
        auto [val, vlen] = decode_bencoded_value(str);
        obj[key.get<std::string>()] = val;
        str = str.substr(vlen);
    }
    return {obj, encode_value.size()-str.size()+1};
}

decoded decode_bencoded_value(const std::string& encoded_value) {
    switch(encoded_value[0]) {
        case 'i': return decode_bencoded_int(encoded_value);
        case 'l': return decode_bencoded_list(encoded_value);
        case 'd': return decode_bencoded_dict(encoded_value);
        default:  return decode_bencoded_str(encoded_value);
    }
}

std::string getIpAddress(const std::string& resp) {
    json response = decode_bencoded_value(resp).first;
    if (!response.contains("peers")) return "";
    auto peers = response["peers"].get<std::string>();
    if (peers.empty()) return "";
    unsigned char ipbytes[4], portbytes[2];
    std::copy(peers.begin(), peers.begin()+4, ipbytes);
    std::copy(peers.begin()+4, peers.begin()+6, portbytes);
    return std::to_string(ipbytes[0]) + "." + std::to_string(ipbytes[1]) + "." +
           std::to_string(ipbytes[2]) + "." + std::to_string(ipbytes[3]) + ":" +
           std::to_string((portbytes[0] << 8) + portbytes[1]);
}

std::string binToHex(const std::string& bin) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : bin) ss << std::setw(2) << static_cast<int>(c);
    return ss.str();
}

std::string hexToBin(const std::string& hex) {
    std::string bin;
    for (size_t i=0; i<hex.size(); i+=2)
        bin += static_cast<char>(std::stoi(hex.substr(i,2), nullptr, 16));
    return bin;
}

std::string readBinaryData(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

info decode_bencoded_info(const std::string& torrent_file) {
    info res;
    auto content = readBinaryData(torrent_file);
    auto [val, _] = decode_bencoded_value(content);
    res.url = val["announce"];
    auto& info = val["info"];
    res.length = info["length"];
    res.pLen = info["piece length"];
    std::string encode_bencode = "d";
    for (const auto& item : info.items()) {
        encode_bencode += std::to_string(item.key().size()) + ":" + item.key();
        if (item.value().is_number())
            encode_bencode += "i" + item.value().dump() + "e";
        else if (item.value().is_string())
            encode_bencode += std::to_string(item.value().get<std::string>().size()) + ":" + item.value().get<std::string>();
    }
    encode_bencode += "e";
    res.hash = sha1(encode_bencode);
    auto hashes = info["pieces"].get<std::string>();
    for (size_t i=0; i<hashes.size(); i+=20)
        res.pHash.push_back(binToHex(hashes.substr(i, 20)));
    return res;
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::vector<char>* buffer) {
    buffer->insert(buffer->end(), (char*)contents, (char*)contents+size*nmemb);
    return size*nmemb;
}

std::string makeGetRequest(const std::string& url) {
    CURL* curl = curl_easy_init();
    std::vector<char> buffer;
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return {buffer.begin(), buffer.end()};
}

void prepareHandShake(std::vector<char>& handShake, const std::string& hashinfo) {
    handShake.push_back(19);
    handShake.insert(handShake.end(), {'B','i','t','T','o','r','r','e','n','t',' ','p','r','o','t','o','c','o','l'});
    handShake.insert(handShake.end(), 8, 0);
    handShake.insert(handShake.end(), hashinfo.begin(), hashinfo.end());
    handShake.insert(handShake.end(), {'0','0','1','1','2','2','3','3','4','4','5','5','6','6','7','7','8','8','9','9'});
}

int connectToPeer(const std::string& ip_port, const info& torrent_info, int& sock) {
    size_t colon = ip_port.find(':');
    if (colon == std::string::npos) return 1;
    std::string ip = ip_port.substr(0, colon);
    int port = std::stoi(ip_port.substr(colon+1));

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 1;

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) return 1;

    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) return 1;

    std::vector<char> handShake;
    prepareHandShake(handShake, torrent_info.hash);
    if (send(sock, handShake.data(), handShake.size(), 0) < 0) return 1;

    std::vector<char> response(68);
    size_t received = 0;
    while (received < 68) {
        ssize_t bytes = recv(sock, response.data()+received, 68-received, 0);
        if (bytes <= 0) return 1;
        received += bytes;
    }
    return 0;
}

void sendInterested(int sock) {
    Msg msg{htonl(1), 2};
    send(sock, &msg, sizeof(msg), 0);
}

int waitForUnchoke(int sock) {
    char buffer[5];
    while (true) {
        if (recv(sock, buffer, 4, 0) != 4) return 0;
        uint32_t len = ntohl(*(uint32_t*)buffer);
        if (len == 0) continue;
        if (recv(sock, buffer+4, 1, 0) != 1) return 0;
        if (buffer[4] == 1) return 1;
        std::vector<char> dummy(len-1);
        recv(sock, dummy.data(), len-1, 0);
    }
}

std::string downloadPiece(int sock, const info& torrent_info, size_t index) {
    size_t piece_size = (index == torrent_info.pHash.size()-1) 
                        ? (torrent_info.length % torrent_info.pLen)
                        : torrent_info.pLen;
    if (piece_size == 0) piece_size = torrent_info.pLen;

    std::string data;
    size_t offset = 0;
    while (data.size() < piece_size) {
        uint32_t block_size = std::min<uint32_t>(16384, piece_size - data.size());
        ReqMsg msg{htonl(13), 6, htonl(index), htonl(offset), htonl(block_size)};
        send(sock, &msg, sizeof(msg), 0);

        char header[4];
        if (recv(sock, header, 4, 0) != 4) return "";
        uint32_t length = ntohl(*(uint32_t*)header);
        std::vector<char> buffer(length);
        size_t received = 0;
        while (received < length) {
            ssize_t bytes = recv(sock, buffer.data()+received, length-received, 0);
            if (bytes <= 0) return "";
            received += bytes;
        }
        if (buffer[0] != 7) return "";
        data.append(buffer.begin()+9, buffer.end());
        offset += block_size;
    }
    return data;
}

void downloadFile(const std::string& torrent, const std::string& output) {
    info torrent_info = decode_bencoded_info(torrent);
    std::string url = constructTrackerURL(torrent_info.url, torrent_info.hash, 
                                        "00112233445566778899", 6881, 0, 0, torrent_info.length, 1);
    std::string response = makeGetRequest(url);
    std::string peer = getIpAddress(response);
    if (peer.empty()) return;

    int sock;
    if (connectToPeer(peer, torrent_info, sock) != 0) return;

    sendInterested(sock);
    if (!waitForUnchoke(sock)) {
        close(sock);
        return;
    }

    std::ofstream out(output, std::ios::binary);
    for (size_t i=0; i<torrent_info.pHash.size(); ++i) {
        std::string piece = downloadPiece(sock, torrent_info, i);
        if (piece.empty() || !verifyPiece(piece, hexToBin(torrent_info.pHash[i]))) {
            close(sock);
            return;
        }
        out.write(piece.data(), piece.size());
    }
    close(sock);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [command]\n";
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "decode") {
        auto [val, _] = decode_bencoded_value(argv[2]);
        std::cout << val.dump() << '\n';
    } 
    else if (cmd == "info") {
        info inf = decode_bencoded_info(argv[2]);
        inf.printInfo();
    } 
    else if (cmd == "peers") {
        std::string url = constructUrlFromTorrent(argv[2]);
        std::string resp = makeGetRequest(url);
        std::cout << decode_bencoded_value(resp).first.dump(4) << '\n';
    } 
    else if (cmd == "handshake" && argc >=4) {
        info inf = decode_bencoded_info(argv[2]);
        int sock;
        if (connectToPeer(argv[3], inf, sock) return 1;
        std::vector<char> resp(68);
        size_t received = 0;
        while (received < 68) {
            ssize_t bytes = recv(sock, resp.data()+received, 68-received, 0);
            if (bytes <=0) break;
            received += bytes;
        }
        if (received == 68) {
            std::string peer_id(resp.end()-20, resp.end());
            std::cout << "Peer ID: " << binToHex(peer_id) << '\n';
        }
        close(sock);
    } 
    else if (cmd == "download_piece" && argc >=6) {
        std::string output = argv[3];
        info inf = decode_bencoded_info(argv[4]);
        int piece_index = std::stoi(argv[5]);
        std::string url = constructUrlFromTorrent(argv[4]);
        std::string peer = getIpAddress(makeGetRequest(url));
        int sock;
        if (connectToPeer(peer, inf, sock)) return 1;
        sendInterested(sock);
        if (!waitForUnchoke(sock)) {
            close(sock);
            return 1;
        }
        std::string data = downloadPiece(sock, inf, piece_index);
        close(sock);
        if (!data.empty() && verifyPiece(data, hexToBin(inf.pHash[piece_index]))) {
            std::ofstream(output, std::ios::binary).write(data.data(), data.size());
            std::cout << "Piece " << piece_index << " downloaded to " << output << '\n';
        }
    } 
    else if (cmd == "download" && argc >=5) {
        downloadFile(argv[4], argv[3]);
    } 
    else {
        std::cerr << "Invalid command\n";
        return 1;
    }
    return 0;
}