#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;
using decoded = std::pair<json, size_t>;

std::string binToHex(const std::string& bin);
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

class WorkQueue {
private:
    std::queue<int> queue;
    std::mutex mtx;
    std::condition_variable cv;
    bool isClosed = false;

public:
    void push(int piece) {
        std::lock_guard<std::mutex> lock(mtx);
        queue.push(piece);
        cv.notify_one();
    }

    int pop() {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [this] { return !queue.empty() || isClosed; });
        if (isClosed) return -1;
        int piece = queue.front();
        queue.pop();
        return piece;
    }

    void close() {
        std::lock_guard<std::mutex> lock(mtx);
        isClosed = true;
        cv.notify_all();
    }

    bool empty() {
        std::lock_guard<std::mutex> lock(mtx);
        return queue.empty();
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

std::vector<std::string> getAllPeers(const std::string& resp) {
    json response = decode_bencoded_value(resp).first;
    std::vector<std::string> ip_ports;
    if (response.contains("peers")) {
        auto peers = response.value("peers", "");
        for (int i = 0; i < peers.size(); i += 6) {
            unsigned char ipbytes[4];
            std::copy(peers.begin() + i, peers.begin() + i + 4, ipbytes);
            std::string ip = std::to_string(ipbytes[0]) + "." + std::to_string(ipbytes[1]) + "."
                           + std::to_string(ipbytes[2]) + "." + std::to_string(ipbytes[3]);
            unsigned char portbytes[2];
            std::copy(peers.begin() + i + 4, peers.begin() + i + 6, portbytes);
            unsigned short port = (portbytes[0] << 8) + portbytes[1];
            ip_ports.push_back(ip + ":" + std::to_string(port));
        }
    }
    return ip_ports;
}

std::string encode_bencoded_value_dict(json &obj) {
    std::string result;
    for (const auto &item: obj.items()) {
        auto key = item.key();
        auto length = std::to_string(key.length());
        result += length + ":";
        result += key;
        auto val = item.value();
        if (val.is_number()) {
            auto num = "i" + val.dump() + "e";
            result += num;
        } else if (val.is_string()) {
            auto str = val.get<std::string>();
            auto len = std::to_string(str.length());
            result += len + ":";
            result += str;
        }
    }
    return result;
}

std::string binToHex(const std::string& bin) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c: bin) {
        ss << std::setw(2) << static_cast<unsigned>(c);
    }
    return ss.str();
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
    size_t length;
    std::string url;
    if (val.contains("announce")) {
        url =  val["announce"];
    }
    if (val.contains("info") && val["info"].is_object()) {
        auto& info = val["info"];
        if (info.contains("length")) {
            length = info["length"];
        }
        std::string encode_bencode = "d";
        encode_bencode += encode_bencoded_value_dict(info);
        encode_bencode += "e";
        auto hash = sha1(encode_bencode);
        res.hash = hash;
        size_t plen = info["piece length"];
        res.pLen = plen;
        auto hashes = info["pieces"];
        if (hashes.is_string()) {
            auto str = hashes.get<std::string>();
            for (int i = 0 ; i < str.size() ; i += 20) {
                std::string chunk = str.substr(i, 20);
                std::string hexChunk = binToHex(chunk);
                res.pHash.push_back(hexChunk);
            }
        }
    }
    res.url = url;
    res.length = length;
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
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        } else {
            response.assign(responseBuffer.begin(), responseBuffer.end());
        }
        curl_easy_cleanup(curl);
    }
    return response;
}

std::string constructUrlFromTorrent(const std::string& filename) {
    auto info = decode_bencoded_info(filename);
    int port = 6881;
    int uploaded = 0;
    int downloaded = 0;
    std::string peerId = "00112233445566778899";
    int left = info.length;
    int compact = 1;
    return constructTrackerURL(info.url, info.hash, peerId, port, uploaded, downloaded, left, compact);
}

void prepareHandShake(std::vector<char>& handShake, std::string hashinfo) {
    char protocolLength = 19;
    handShake.push_back(protocolLength);
    std::string protocol = "BitTorrent protocol";
    handShake.insert(handShake.end(), protocol.begin(), protocol.end());
    for (int i = 0; i < 8 ; ++i) {
        handShake.push_back(0);
    }
    handShake.insert(handShake.end(), hashinfo.begin(), hashinfo.end());
    std::string peerId = "00112233445566778899";
    handShake.insert(handShake.end(), peerId.begin(), peerId.end());
}

int sendMessage(int sock, const std::vector<char>& message) {
    if(send(sock, message.data(), message.size(), 0) <0) {
        return 0;
    }
    return 1;
}

void sendInterested(int sock) {
    Msg interestedMsg = {htonl(1), 2};
    sendMessage(sock, std::vector<char>(reinterpret_cast<char*>(&interestedMsg),
                                        reinterpret_cast<char*>(&interestedMsg) + sizeof(interestedMsg)));
}

void sendRequest(int sock, uint32_t index, uint32_t begin, uint32_t length_block) {
    ReqMsg reqMsg = {htonl(13), 6, htonl(index), htonl(begin), htonl(length_block)};
    sendMessage(sock, std::vector<char>(reinterpret_cast<char*>(&reqMsg),
                                        reinterpret_cast<char*>(&reqMsg) + sizeof(reqMsg)));
}

bool verifyPiece(const std::string& piece_data, const std::string& expected_hash_hex) {
    std::string computed_hash = sha1(piece_data);
    std::string computed_hash_hex = binToHex(computed_hash);
    return computed_hash_hex == expected_hash_hex;
}

int waitForUnchoke(int sock) {
    const int bufferSize = 4;
    char buffer[bufferSize];
    while (true) {
        memset(buffer, 0, bufferSize);
        if(recv(sock, buffer, bufferSize, 0) < 0) {
            break;
        }
        uint32_t msgLength = ntohl(*reinterpret_cast<uint32_t*>(buffer));
        if (msgLength == 0) {
            continue;
        }
        if(msgLength < 1)  {
            break;
        }
        char msgID;
        if(recv(sock, &msgID, 1, 0) < 0) {
            break;
        }
        if (msgID == 1) {
            return 1;
        } else {
            std::vector<char> dummyBuffer(msgLength - 1);
            if(recv(sock, dummyBuffer.data(), msgLength - 1, 0) < 0) {
                break;
            }
        }
    }
    return 0;
}

int SendRecvHandShake(std::string torrent_file, std::string ipaddress, int &sock) {
    auto info = decode_bencoded_info(torrent_file);
    std::string server_ip;
    int port;
    size_t colon_pos = ipaddress.find(':');
    if (colon_pos == std::string::npos) {
        return 1;
    }
    server_ip = ipaddress.substr(0, colon_pos);
    port = std::stoi(ipaddress.substr(colon_pos+1));
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 1;
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        return 1;
    }
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0 ) {
        return 1;
    }
    std::vector<char> handShakeMsg;
    prepareHandShake(handShakeMsg, info.hash);
    if (send(sock, handShakeMsg.data(), handShakeMsg.size(), 0) < 0) {
        return 1;
    }
    std::vector<char> handShakeResp(handShakeMsg.size());
    if(recv(sock, handShakeResp.data(), handShakeResp.size(), 0) < 0) {
        return 1;
    }
    return 0;
}

void downloadAllPieces(const std::string& torrent, const std::string& output_path) {
    info torrent_info = decode_bencoded_info(torrent);
    std::string tracker_url = constructUrlFromTorrent(torrent);
    std::string tracker_response = makeGetRequest(tracker_url);
    std::vector<std::string> peers = getAllPeers(tracker_response);

    WorkQueue work_queue;
    for (int i = 0; i < torrent_info.pHash.size(); ++i) {
        work_queue.push(i);
    }

    std::ofstream outfile(output_path, std::ios::binary | std::ios::trunc);
    if (!outfile) {
        std::cerr << "Failed to open output file: " << output_path << std::endl;
        return;
    }
    outfile.seekp(torrent_info.length - 1);
    outfile.write("", 1);
    outfile.close();

    std::fstream file(output_path, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file for writing: " << output_path << std::endl;
        return;
    }

    std::mutex file_mutex;
    std::vector<std::thread> threads;

    for (const auto& peer : peers) {
        threads.emplace_back([peer, &torrent, &work_queue, &file, &file_mutex, &torrent_info]() {
            int sock;
            if (SendRecvHandShake(torrent, peer, sock) != 0) {
                return;
            }
            sendInterested(sock);
            if (!waitForUnchoke(sock)) {
                close(sock);
                return;
            }

            while (true) {
                int piece_index = work_queue.pop();
                if (piece_index == -1) break;

                size_t piece_length = torrent_info.pLen;
                size_t total_size = torrent_info.length;
                size_t piece_size = (piece_index == torrent_info.pHash.size() - 1) ? (total_size % piece_length) : piece_length;
                if (piece_size == 0) piece_size = piece_length;

                std::string piece_data;
                size_t remaining = piece_size;
                size_t offset = 0;
                bool failed = false;

                while (remaining > 0 && !failed) {
                    size_t block_length = std::min((size_t)16384, remaining);
                    sendRequest(sock, piece_index, offset, block_length);

                    std::vector<char> length_buf(4);
                    if (recv(sock, length_buf.data(), 4, 0) != 4) {
                        failed = true;
                        break;
                    }
                    uint32_t message_length = ntohl(*reinterpret_cast<uint32_t*>(length_buf.data()));
                    std::vector<char> message(message_length);
                    size_t received = 0;
                    while (received < message_length) {
                        int bytes = recv(sock, message.data() + received, message_length - received, 0);
                        if (bytes <= 0) {
                            failed = true;
                            break;
                        }
                        received += bytes;
                    }
                    if (failed) break;

                    if (message[0] == 7) {
                        std::string block_data(message.begin() + 9, message.end());
                        piece_data += block_data;
                        remaining -= block_data.size();
                        offset += block_data.size();
                    } else {
                        failed = true;
                        break;
                    }
                }

                if (!failed && piece_data.size() == piece_size) {
                    std::string expected_hash = torrent_info.pHash[piece_index];
                    if (!verifyPiece(piece_data, expected_hash)) {
                        failed = true;
                    }
                } else {
                    failed = true;
                }

                if (failed) {
                    work_queue.push(piece_index);
                } else {
                    std::lock_guard<std::mutex> lock(file_mutex);
                    file.seekp(piece_index * torrent_info.pLen);
                    file.write(piece_data.data(), piece_data.size());
                    if (!file) {
                        work_queue.push(piece_index);
                    }
                }
            }
            close(sock);
        });
    }

    // Allow some time for all threads to process before closing the queue
    std::this_thread::sleep_for(std::chrono::seconds(10));
    work_queue.close();

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    file.close();
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }
    std::string command = argv[1];
    if (command == "decode") {
        std::string encoded_value = argv[2];
        json decoded_value = decode_bencoded_value(encoded_value).first;
        std::cout << decoded_value.dump() << std::endl;
    } else if (command == "info") {
        std::string torrent = argv[2];
        info inf = decode_bencoded_info(torrent);
        inf.printInfo();
    } else if (command == "peers") {
        std::string torrent = argv[2];
        auto fullUrl = constructUrlFromTorrent(torrent);
        auto response = makeGetRequest(fullUrl);
        json decoded_response = decode_bencoded_value(response).first;
        std::cout << decoded_response.dump(4) << std::endl;
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
        downloadAllPieces(torrent, output_path);
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }
    return 0;
}