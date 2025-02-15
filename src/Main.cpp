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
public:
    std::string url;
    size_t length;
    std::string hash;
    size_t pLen;
    std::vector<std::string> pHash;
    void printInfo() const {
        std::cout << "Tracker URL: " << url << std::endl;
        std::cout << "Length: " << length << std::endl;
        std::cout << "Info Hash: " << binToHex(hash) << std::endl;
        std::cout << "Piece Length: " << pLen << std::endl;
        std::cout << "Piece Hashes:" << std::endl;
        for (auto it : pHash) {
            std::cout << it << std::endl;
        }
    }
};

std::string urlEncode(const std::string& url) {
    char *encoded = curl_easy_escape(nullptr, url.c_str(), url.length());
    std::string res(encoded);
    curl_free(encoded);
    return res;
}

std::string constructTrackerURL(const std::string& trackerUrl,
                                const std::string& inf_hash,
                                const std::string& peerId,
                                int port,
                                int uploaded,
                                int downloaded,
                                int left,
                                int compact) {
    std::string infoHash = urlEncode(inf_hash);
    std::ostringstream ss;
    ss << trackerUrl << "?"
        << "info_hash=" << infoHash << "&"
        << "peer_id=" << peerId << "&"
        << "port=" << port << "&"
        << "uploaded=" << uploaded << "&"
        << "downloaded=" << downloaded << "&"
        << "left=" << left << "&"
        << "compact=" << compact;
    return ss.str();
}

std::string sha1(const std::string& inp) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(inp.c_str()), inp.size(), hash);
    return std::string(reinterpret_cast<const char*>(hash), SHA_DIGEST_LENGTH);
}

decoded decode_bencoded_value(const std::string& encoded_value);

decoded decode_bencoded_str(const std::string& str) {
    size_t colon = str.find(':');
    if(colon != std::string::npos) {
        int64_t number = std::stoll(str.substr(0, colon));
        std::string res = str.substr(colon+1, number);
        return {json(res), number+colon+1};
    } else {
        throw std::runtime_error("Invalid encode value: " + str);
    }
}

decoded decode_bencoded_int(const std::string& encoded_value) {
    size_t pos = encoded_value.find('e');
    if (pos != std::string::npos) {
        std::string number_part = encoded_value.substr(1, pos);
        if (number_part == "-0" || (number_part[0] == '0' && number_part.size() < 1) || (number_part[0] == '-' && number_part[1] == '0')) {
            throw std::runtime_error("Invalid integer encoding: " + encoded_value);
        }
        long long int val = std::stoll(number_part);
        return {json(val), pos+1};
    } else {
        throw std::runtime_error("Invalid encoded value: " + encoded_value);
    }
}

decoded decode_bencoded_list(const std::string& encode_value) {
    std::string str = encode_value.substr(1);
    json arr = json::array();
    while(str[0] != 'e') {
        auto decod = decode_bencoded_value(str);
        arr.push_back(decod.first);
        str = str.substr(decod.second);
    }
    return {arr, encode_value.length()-str.length()+1};
}

decoded decode_bencoded_dict(const std::string& encode_value) {
    std::string str = encode_value.substr(1);
    json obj = json::object();
    while(str[0] != 'e') {
        std::string key;
        {
            auto decod = decode_bencoded_str(str);
            key = decod.first;
            str = str.substr(decod.second);
        }
        auto decod = decode_bencoded_value(str);
        obj[key] = decod.first;
        str = str.substr(decod.second);
    }
    return {obj, encode_value.length()-str.length() + 1};
}

decoded decode_bencoded_value(const std::string& encoded_value) {
    if (std::isdigit(encoded_value[0])) {
        return decode_bencoded_str(encoded_value);
    } else if (encoded_value[0] == 'i') {
        return decode_bencoded_int(encoded_value);
    } else if (encoded_value[0] == 'l') {
        return decode_bencoded_list(encoded_value);
    } else if (encoded_value[0] == 'd') {
        return decode_bencoded_dict(encoded_value);
    } else {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

std::string getIpAddress(const std::string& resp) {
    json response = decode_bencoded_value(resp).first;
    std::vector<std::string> ip_ports;
    if (response.contains("peers")) {
        auto peers = response.value("peers", "");
        for (int i = 0 ; i < peers.size() ; i+=6) {
            unsigned char ipbytes[4];
            std::copy(peers.begin() + i , peers.begin() + i + 4, ipbytes);
            std::string ip = std::to_string(ipbytes[0]) + "." + std::to_string(ipbytes[1]) + "." +
                            std::to_string(ipbytes[2]) + "." + std::to_string(ipbytes[3]);
            unsigned char portbytes[2];
            std::copy(peers.begin() + i + 4 , peers.begin() + i + 6 , portbytes);
            unsigned short port = (portbytes[0] << 8) + portbytes[1];
            std::string ip_port = ip + ":" + std::to_string(port);
            ip_ports.push_back(ip_port);
        }
    }
    if (!ip_ports.empty()) {
        return ip_ports[0];
    }
    return "";
}

std::string binToHex(const std::string& bin) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : bin) {
        ss << std::setw(2) << static_cast<unsigned>(c);
    }
    return ss.str();
}

std::string hexToBin(const std::string& hex) {
    std::string bin;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte = hex.substr(i, 2);
        char c = static_cast<char>(std::stoi(byte, nullptr, 16));
        bin.push_back(c);
    }
    return bin;
}

std::string readBinaryData(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Error opening the file: " + filename);
    }
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    file.close();
    return std::string(buffer.begin(), buffer.end());
}

info decode_bencoded_info(const std::string& torrent_file) {
    info res;
    auto content = readBinaryData(torrent_file);
    auto val = decode_bencoded_value(content).first;
    if (val.contains("announce")) {
        res.url = val["announce"];
    }
    if (val.contains("info") && val["info"].is_object()) {
        auto& info = val["info"];
        if (info.contains("length")) {
            res.length = info["length"];
        }
        std::string encode_bencode = "d";
        for (const auto& item : info.items()) {
            encode_bencode += std::to_string(item.key().size()) + ":" + item.key();
            if (item.value().is_number()) {
                encode_bencode += "i" + item.value().dump() + "e";
            } else if (item.value().is_string()) {
                encode_bencode += std::to_string(item.value().get<std::string>().size()) + ":" + item.value().get<std::string>();
            }
        }
        encode_bencode += "e";
        res.hash = sha1(encode_bencode);
        res.pLen = info["piece length"];
        auto hashes = info["pieces"];
        if (hashes.is_string()) {
            auto str = hashes.get<std::string>();
            for (size_t i = 0; i < str.size(); i += 20) {
                res.pHash.push_back(binToHex(str.substr(i, 20)));
            }
        }
    }
    return res;
}

size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::vector<char>* buffer) {
    size_t newLength = size * nmemb;
    buffer->insert(buffer->end(), (char*)contents, (char*)contents + newLength);
    return newLength;
}

std::string makeGetRequest(const std::string& url) {
    CURL* curl = curl_easy_init();
    std::string response;
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        std::vector<char> responseBuffer;
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            response.assign(responseBuffer.begin(), responseBuffer.end());
        }
        curl_easy_cleanup(curl);
    }
    return response;
}

std::string constructUrlFromTorrent(const std::string& filename) {
    auto info = decode_bencoded_info(filename);
    std::string peerId = "00112233445566778899";
    return constructTrackerURL(info.url, info.hash, peerId, 6881, 0, 0, info.length, 1);
}

void prepareHandShake(std::vector<char>& handShake, const std::string& hashinfo) {
    handShake.push_back(19);
    std::string protocol = "BitTorrent protocol";
    handShake.insert(handShake.end(), protocol.begin(), protocol.end());
    for (int i = 0; i < 8; ++i) handShake.push_back(0);
    handShake.insert(handShake.end(), hashinfo.begin(), hashinfo.end());
    std::string peerId = "00112233445566778899";
    handShake.insert(handShake.end(), peerId.begin(), peerId.end());
}

int sendMessage(int sock, const std::vector<char>& message) {
    return send(sock, message.data(), message.size(), 0) > 0;
}

void sendInterested(int sock) {
    Msg interestedMsg = {htonl(1), 2};
    sendMessage(sock, std::vector<char>(reinterpret_cast<char*>(&interestedMsg), reinterpret_cast<char*>(&interestedMsg) + sizeof(interestedMsg)));
}

void sendRequest(int sock, uint32_t index, uint32_t begin, uint32_t length_block) {
    ReqMsg reqMsg = {htonl(13), 6, htonl(index), htonl(begin), htonl(length_block)};
    sendMessage(sock, std::vector<char>(reinterpret_cast<char*>(&reqMsg), reinterpret_cast<char*>(&reqMsg) + sizeof(reqMsg)));
}

bool verifyPiece(const std::string& piece_data, const std::string& expected_hash_hex) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(piece_data.c_str()), piece_data.size(), hash);
    std::string actual_hash_hex = binToHex(std::string(reinterpret_cast<const char*>(hash), SHA_DIGEST_LENGTH));
    return actual_hash_hex == expected_hash_hex;
}

int waitForUnchoke(int sock) {
    char buffer[4];
    while (true) {
        if (recv(sock, buffer, 4, 0) < 4) return 0;
        uint32_t msgLength = ntohl(*reinterpret_cast<uint32_t*>(buffer));
        if (msgLength == 0) continue;
        char msgID;
        if (recv(sock, &msgID, 1, 0) < 1) return 0;
        if (msgID == 1) return 1;
        std::vector<char> dummy(msgLength - 1);
        if (recv(sock, dummy.data(), msgLength - 1, 0) < 0) return 0;
    }
}

int connectToPeer(const std::string& ip_port, const info& torrent_info, int& sock) {
    size_t colon = ip_port.find(':');
    if (colon == std::string::npos) return 1;
    std::string ip = ip_port.substr(0, colon);
    int port = std::stoi(ip_port.substr(colon + 1));

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 1;

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) return 1;

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) return 1;

    std::vector<char> handShake;
    prepareHandShake(handShake, torrent_info.hash);
    if (send(sock, handShake.data(), handShake.size(), 0) < 0) return 1;
    std::vector<char> response(handShake.size());
    if (recv(sock, response.data(), response.size(), 0) < 0) return 1;

    return 0;
}

std::string downloadPiece(int sock, const info& torrent_info, size_t piece_index) {
    size_t piece_length = torrent_info.pLen;
    size_t total_size = torrent_info.length;
    size_t num_pieces = (total_size + piece_length - 1) / piece_length;
    size_t current_size = (piece_index == num_pieces - 1) ? (total_size % piece_length) : piece_length;
    if (current_size == 0) current_size = piece_length;

    std::string piece_data;
    size_t remaining = current_size;
    size_t offset = 0;
    const size_t block_size = 16384;

    while (remaining > 0) {
        size_t request_size = std::min(block_size, remaining);
        sendRequest(sock, piece_index, offset, request_size);

        char length_buf[4];
        if (recv(sock, length_buf, 4, 0) != 4) {
            return "";
        }
        uint32_t message_length = ntohl(*reinterpret_cast<uint32_t*>(length_buf));
        std::vector<char> message(message_length);
        int received = 0;
        while (received < message_length) {
            int bytes = recv(sock, message.data() + received, message_length - received, 0);
            if (bytes <= 0) return "";
            received += bytes;
        }

        if (message[0] == 7) {
            size_t data_length = message_length - 9;
            piece_data.append(message.data() + 9, data_length);
            remaining -= data_length;
            offset += data_length;
        } else {
            return "";
        }
    }

    return piece_data;
}

void downloadFile(const std::string& torrent_file, const std::string& output_path) {
    info torrent_info = decode_bencoded_info(torrent_file);
    std::string tracker_url = constructUrlFromTorrent(torrent_file);
    std::string response = makeGetRequest(tracker_url);
    std::string peer_address = getIpAddress(response);
    if (peer_address.empty()) {
        std::cerr << "No peers found" << std::endl;
        return;
    }

    int sock;
    if (connectToPeer(peer_address, torrent_info, sock) != 0) {
        std::cerr << "Failed to connect to peer" << std::endl;
        return;
    }

    sendInterested(sock);
    if (!waitForUnchoke(sock)) {
        std::cerr << "Failed to receive unchoke" << std::endl;
        close(sock);
        return;
    }

    std::ofstream outfile(output_path, std::ios::binary);
    if (!outfile) {
        std::cerr << "Failed to open output file" << std::endl;
        close(sock);
        return;
    }
    outfile.close();
    outfile.open(output_path, std::ios::binary | std::ios::in | std::ios::out);

    size_t num_pieces = torrent_info.pHash.size();
    for (size_t i = 0; i < num_pieces; ++i) {
        std::string piece_data;
        bool verified = false;
        int retries = 3;
        while (!verified && retries-- > 0) {
            piece_data = downloadPiece(sock, torrent_info, i);
            if (piece_data.empty()) {
                std::cerr << "Failed to download piece " << i << std::endl;
                continue;
            }
            verified = verifyPiece(piece_data, torrent_info.pHash[i]);
            if (!verified) {
                std::cerr << "Verification failed for piece " << i << ", retrying..." << std::endl;
            }
        }
        if (!verified) {
            std::cerr << "Failed to download piece " << i << " after retries" << std::endl;
            break;
        }
        size_t offset = i * torrent_info.pLen;
        outfile.seekp(offset);
        outfile.write(piece_data.data(), piece_data.size());
        outfile.flush();
    }

    outfile.close();
    close(sock);
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }
    std::string command = argv[1];
    if (command == "decode") {
        std::string encoded_value = argv[2];
        json decoded_value = decode_bencoded_value(encoded_value).first;
        std::cout << decoded_value.dump() << std::endl;
    } else if (command == "info") {
        info inf = decode_bencoded_info(argv[2]);
        inf.printInfo();
    } else if (command == "peers") {
        std::string url = constructUrlFromTorrent(argv[2]);
        std::string resp = makeGetRequest(url);
        json j = decode_bencoded_value(resp).first;
        std::cout << j.dump(4) << std::endl;
    } else if (command == "handshake") {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " handshake <torrent> <peer_ip>:<peer_port>" << std::endl;
            return 1;
        }
        std::string torrent = argv[2];
        std::string ipaddress = argv[3];
        int sock;
        if (SendRecvHandShake(torrent, ipaddress, sock) == 0) {
            std::vector<char> handShakeResp(68);
            if(recv(sock, handShakeResp.data(), handShakeResp.size(), 0) < 0) {
                std::cerr << "Failed to receive handshake response" << std::endl;
            } else {
                std::string peer_id(handShakeResp.end() - 20, handShakeResp.end());
                std::cout << "Peer ID: " << binToHex(peer_id) << std::endl;
            }
            close(sock);
        }
    } else if (command == "download_piece") {
        if (argc < 5) {
            std::cerr << "Usage: " << argv[0] << " download_piece -o <output_file> <torrent> <piece_index>" << std::endl;
            return 1;
        }
        std::string output_path = argv[3];
        std::string torrent = argv[4];
        int piece_index = std::stoi(argv[5]);
        // Single piece download logic here (not implemented in this example)
    } else if (command == "download") {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " download -o <output_file> <torrent>" << std::endl;
            return 1;
        }
        std::string output_path = argv[3];
        std::string torrent = argv[4];
        downloadFile(torrent, output);
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }
    return 0;
}