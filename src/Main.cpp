#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <curl/curl.h>
#include <random>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <map>
#include <algorithm>
#include "lib/nlohmann/json.hpp"
#include "lib/sha1.hpp"
using json = nlohmann::json;

// Function declarations
json decode_integer(const std::string& encoded_value, size_t& index);
json decode_string(const std::string& encoded_value, size_t& index);
json decode_list(const std::string& encoded_value, size_t& index);
json decode_dictionary(const std::string& encoded_value, size_t& index);
json decode_value(const std::string& encoded_value, size_t& index);
json decode_bencoded_value(const std::string& encoded_value);
std::string read_file(const std::string& file_path);
std::string json_to_bencode(const json& j);
void parse_torrent(const std::string& file_path);
std::vector<std::string> get_peers(const std::string& tracker_url, const std::string& info_hash, int file_length);
int perform_handshake(const std::string& file_path, const std::string& peer_ip_port, std::string& received_peer_id);
void download_piece(const std::string& file_path, const std::string& output_path, int piece_index);

std::string generate_peer_id() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::string peer_id;
    for (int i = 0; i < 20; ++i) {
        peer_id.push_back(static_cast<char>(dis(gen)));
    }
    return peer_id;
}

json decode_value(const std::string& encoded_value, size_t& index) {
    char type = encoded_value[index];
    switch (type) {
        case 'i':
            return decode_integer(encoded_value, index);
        case 'l':
            return decode_list(encoded_value, index);
        case 'd':
            return decode_dictionary(encoded_value, index);
        default:
            if (std::isdigit(type)) {
                return decode_string(encoded_value, index);
            } else {
                throw std::runtime_error("Invalid encoded value.");
            }
    }
}

json decode_integer(const std::string& encoded_value, size_t& index) {
    size_t start = index + 1;
    size_t end = encoded_value.find('e', start);
    if (end == std::string::npos) {
        throw std::runtime_error("Invalid integer encoding.");
    }
    std::string num_str = encoded_value.substr(start, end - start);
    int64_t num = std::atoll(num_str.c_str());
    index = end + 1;
    return json(num);
}

json decode_string(const std::string& encoded_value, size_t& index) {
    size_t colon = encoded_value.find(':', index);
    if (colon == std::string::npos) {
        throw std::runtime_error("Invalid string encoding.");
    }
    int length = std::stoi(encoded_value.substr(index, colon - index));
    std::string result = encoded_value.substr(colon + 1, length);
    index = colon + 1 + length;
    return json(result);
}

json decode_list(const std::string& encoded_value, size_t& index) {
    index++;
    std::vector<json> list;
    while (index < encoded_value.length() && encoded_value[index] != 'e') {
        list.push_back(decode_value(encoded_value, index));
    }
    index++;
    return json(list);
}

json decode_dictionary(const std::string& encoded_value, size_t& index) {
    index++;
    json dict = json::object();
    while (index < encoded_value.length() && encoded_value[index] != 'e') {
        json key = decode_string(encoded_value, index);
        json value = decode_value(encoded_value, index);
        dict[key.get<std::string>()] = value;
    }
    index++;
    return dict;
}

json decode_bencoded_value(const std::string& encoded_value) {
    size_t index = 0;
    return decode_value(encoded_value, index);
}

std::string read_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    std::stringstream buffer;
    if (file) {
        buffer << file.rdbuf();
        file.close();
        return buffer.str();
    } else {
        throw std::runtime_error("Failed to open file: " + file_path);
    }
}

std::string json_to_bencode(const json& j) {
    std::ostringstream os;
    if (j.is_object()) {
        os << 'd';
        for (auto& el : j.items()) {
            os << el.key().size() << ':' << el.key() << json_to_bencode(el.value());
        }
        os << 'e';
    } else if (j.is_array()) {
        os << 'l';
        for (const json& item : j) {
            os << json_to_bencode(item);
        }
        os << 'e';
    } else if (j.is_number_integer()) {
        os << 'i' << j.get<int>() << 'e';
    } else if (j.is_string()) {
        const std::string& value = j.get<std::string>();
        os << value.size() << ':' << value;
    }
    return os.str();
}

void parse_torrent(const std::string& file_path) {
    std::string content = read_file(file_path);
    json decoded_torrent = decode_bencoded_value(content);
    std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string info_hash = sha1.final();

    std::string tracker_url = decoded_torrent["announce"];
    int length = decoded_torrent["info"]["length"];
    int piece_length = decoded_torrent["info"]["piece length"];
    std::string pieces = decoded_torrent["info"]["pieces"];

    std::cout << "Tracker URL: " << tracker_url << std::endl;
    std::cout << "Length: " << length << std::endl;
    std::cout << "Info Hash: " << info_hash << std::endl;
    std::cout << "Piece Length: " << piece_length << std::endl;
    std::cout << "Piece Hashes: " << std::endl;

    for (size_t i = 0; i < pieces.size(); i += 20) {
        std::string piece_hash = pieces.substr(i, 20);
        std::stringstream ss;
        for (unsigned char byte : piece_hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << ss.str() << std::endl;
    }
}

size_t write_callback(void* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append((char*)ptr, size * nmemb);
    return size * nmemb;
}

std::vector<std::string> get_peers(const std::string& tracker_url, const std::string& info_hash, int file_length) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL.");
    }

    std::string peer_id = generate_peer_id();
    std::string port = "6881";
    std::string uploaded = "0";
    std::string downloaded = "0";
    std::string left = std::to_string(file_length);
    std::string compact = "1";

    char* encoded_info_hash = curl_easy_escape(curl, info_hash.c_str(), info_hash.size());
    if (!encoded_info_hash) {
        throw std::runtime_error("Failed to URL encode info hash.");
    }

    std::string full_url = tracker_url + "?info_hash=" + encoded_info_hash +
                           "&peer_id=" + peer_id +
                           "&port=" + port +
                           "&uploaded=" + uploaded +
                           "&downloaded=" + downloaded +
                           "&left=" + left +
                           "&compact=" + compact;

    std::string response_data;
    curl_easy_setopt(curl, CURLOPT_URL, full_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

    CURLcode res = curl_easy_perform(curl);
    curl_free(encoded_info_hash);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error("Failed to query tracker: " + std::string(curl_easy_strerror(res)));
    }

    json tracker_response = decode_bencoded_value(response_data);
    std::string peers = tracker_response["peers"];

    std::vector<std::string> peer_list;
    for (size_t i = 0; i < peers.size(); i += 6) {
        std::string peer = peers.substr(i, 6);
        std::string ip = std::to_string((unsigned char)peer[0]) + "." +
                         std::to_string((unsigned char)peer[1]) + "." +
                         std::to_string((unsigned char)peer[2]) + "." +
                         std::to_string((unsigned char)peer[3]);
        int port = (unsigned char)peer[4] * 256 + (unsigned char)peer[5];
        peer_list.push_back(ip + ":" + std::to_string(port));
    }

    return peer_list;
}

int perform_handshake(const std::string& file_path, const std::string& peer_ip_port, std::string& received_peer_id) {
    std::string content = read_file(file_path);
    json decoded_torrent = decode_bencoded_value(content);
    std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string hex_hash = sha1.final();

    std::string info_hash_raw;
    for (size_t i = 0; i < hex_hash.size(); i += 2) {
        std::string byte_str = hex_hash.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
        info_hash_raw.push_back(byte);
    }

    std::string peer_id = generate_peer_id();

    size_t colon_pos = peer_ip_port.find(':');
    if (colon_pos == std::string::npos) {
        throw std::runtime_error("Invalid peer IP:port format.");
    }
    std::string peer_ip = peer_ip_port.substr(0, colon_pos);
    int peer_port = std::stoi(peer_ip_port.substr(colon_pos + 1));

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        throw std::runtime_error("Failed to create socket.");
    }

    struct sockaddr_in peer_addr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    if (inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr) <= 0) {
        close(sock);
        throw std::runtime_error("Invalid peer IP address.");
    }

    if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        close(sock);
        throw std::runtime_error("Failed to connect to peer.");
    }

    std::string handshake;
    handshake.push_back(19);
    handshake += "BitTorrent protocol";
    handshake += std::string(8, '\0');
    handshake += info_hash_raw;
    handshake += peer_id;

    if (send(sock, handshake.c_str(), handshake.size(), 0) < 0) {
        close(sock);
        throw std::runtime_error("Failed to send handshake.");
    }

    char buffer[68];
    if (recv(sock, buffer, sizeof(buffer), MSG_WAITALL) < 0) {
        close(sock);
        throw std::runtime_error("Failed to receive handshake response.");
    }

    received_peer_id = std::string(buffer + 48, 20);
    return sock;
}

void download_piece(const std::string& file_path, const std::string& output_path, int piece_index) {
    std::string content = read_file(file_path);
    json decoded_torrent = decode_bencoded_value(content);
    std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string hex_hash = sha1.final();

    std::string info_hash_raw = hex_hash;
    

    int piece_length = decoded_torrent["info"]["piece length"];
    int total_length = decoded_torrent["info"]["length"];
    std::string pieces = decoded_torrent["info"]["pieces"];
    int num_pieces = (total_length + piece_length - 1) / piece_length;
    if (piece_index < 0 || piece_index >= num_pieces) {
        throw std::runtime_error("Invalid piece index");
    }

    int piece_start = piece_index * piece_length;
    int piece_end = std::min((piece_index + 1) * piece_length, total_length);
    int piece_size = piece_end - piece_start;

    std::string tracker_url = decoded_torrent["announce"];
    std::vector<std::string> peers = get_peers(tracker_url, info_hash_raw, total_length);
    if (peers.empty()) {
        throw std::runtime_error("No peers found");
    }
    std::string peer_ip_port = peers[0];

    std::string received_peer_id;
    int sock = perform_handshake(file_path, peer_ip_port, received_peer_id);

    bool got_bitfield = false;
    while (!got_bitfield) {
        char len_buf[4];
        if (recv(sock, len_buf, 4, MSG_WAITALL) != 4) {
            close(sock);
            throw std::runtime_error("Failed to read message length");
        }
        uint32_t message_length = ntohl(*reinterpret_cast<uint32_t*>(len_buf));
        if (message_length == 0) continue;
        std::vector<char> message(message_length);
        if (recv(sock, message.data(), message_length, MSG_WAITALL) != message_length) {
            close(sock);
            throw std::runtime_error("Failed to read message");
        }
        if (message[0] == 5) {
            got_bitfield = true;
        }
    }

    std::vector<char> interested_msg(5);
    uint32_t interested_len = htonl(1);
    memcpy(interested_msg.data(), &interested_len, 4);
    interested_msg[4] = 2;
    if (send(sock, interested_msg.data(), interested_msg.size(), 0) != interested_msg.size()) {
        close(sock);
        throw std::runtime_error("Failed to send interested message");
    }

    bool unchoked = false;
    while (!unchoked) {
        char len_buf[4];
        if (recv(sock, len_buf, 4, MSG_WAITALL) != 4) {
            close(sock);
            throw std::runtime_error("Failed to read message length");
        }
        uint32_t message_length = ntohl(*reinterpret_cast<uint32_t*>(len_buf));
        if (message_length == 0) continue;
        std::vector<char> message(message_length);
        if (recv(sock, message.data(), message_length, MSG_WAITALL) != message_length) {
            close(sock);
            throw std::runtime_error("Failed to read message");
        }
        if (message[0] == 1) {
            unchoked = true;
        } else if (message[0] == 0) {
            close(sock);
            throw std::runtime_error("Peer choked us");
        }
    }

    const int block_size = 16384;
    int num_blocks = (piece_size + block_size - 1) / block_size;
    std::vector<char> piece_data(piece_size);

    for (int block = 0; block < num_blocks; block++) {
        int begin = block * block_size;
        int length = std::min(block_size, piece_size - begin);

        std::vector<char> request_msg(17);
        uint32_t req_len = htonl(13);
        memcpy(request_msg.data(), &req_len, 4);
        request_msg[4] = 6;
        uint32_t index = htonl(piece_index);
        memcpy(request_msg.data() + 5, &index, 4);
        uint32_t begin_net = htonl(begin);
        memcpy(request_msg.data() + 9, &begin_net, 4);
        uint32_t length_net = htonl(length);
        memcpy(request_msg.data() + 13, &length_net, 4);

        if (send(sock, request_msg.data(), request_msg.size(), 0) != request_msg.size()) {
            close(sock);
            throw std::runtime_error("Failed to send request message");
        }
    }

    int received_blocks = 0;
    while (received_blocks < num_blocks) {
        char len_buf[4];
        if (recv(sock, len_buf, 4, MSG_WAITALL) != 4) {
            close(sock);
            throw std::runtime_error("Failed to read message length");
        }
        uint32_t message_length = ntohl(*reinterpret_cast<uint32_t*>(len_buf));
        if (message_length == 0) continue;
        std::vector<char> message(message_length);
        if (recv(sock, message.data(), message_length, MSG_WAITALL) != message_length) {
            close(sock);
            throw std::runtime_error("Failed to read message");
        }
        if (message[0] == 7) {
            uint32_t index = ntohl(*reinterpret_cast<uint32_t*>(message.data() + 1));
            uint32_t begin = ntohl(*reinterpret_cast<uint32_t*>(message.data() + 5));
            const char* block = message.data() + 9;
            uint32_t block_length = message_length - 9;

            if (index != piece_index) continue;

            if (begin + block_length > piece_size) {
                close(sock);
                throw std::runtime_error("Invalid block data");
            }

            std::copy(block, block + block_length, piece_data.begin() + begin);
            received_blocks++;
        }
    }

    std::string piece_hash = pieces.substr(piece_index * 20, 20);
    SHA1 sha;
    std::string piece_data_str(piece_data.begin(), piece_data.end());
    sha.update(piece_data_str);
    std::string computed_hash = sha.final();

    if (computed_hash != piece_hash) {
        close(sock);
        throw std::runtime_error("Piece hash mismatch");
    }

    std::ofstream out_file(output_path, std::ios::binary);
    if (!out_file) {
        close(sock);
        throw std::runtime_error("Failed to open output file");
    }
    out_file.write(piece_data.data(), piece_data.size());
    out_file.close();

    close(sock);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value> | info <torrent_file> | peers <torrent_file> | handshake <torrent_file> <peer_ip>:<peer_port> | download_piece -o <output_file> <torrent_file> <piece_index>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        try {
            std::string encoded_value = argv[2];
            json decoded_value = decode_bencoded_value(encoded_value);
            std::cout << decoded_value.dump() << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error decoding: " << e.what() << std::endl;
            return 1;
        }
    } else if (command == "info") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " info <torrent_file>" << std::endl;
            return 1;
        }
        try {
            parse_torrent(argv[2]);
        } catch (const std::exception& e) {
            std::cerr << "Error getting info: " << e.what() << std::endl;
            return 1;
        }
    } else if (command == "peers") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " peers <torrent_file>" << std::endl;
            return 1;
        }
        try {
            std::string content = read_file(argv[2]);
            json decoded_torrent = decode_bencoded_value(content);
            std::string tracker_url = decoded_torrent["announce"];
            int length = decoded_torrent["info"]["length"];
            std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);
            SHA1 sha1;
            sha1.update(bencoded_info);
            std::string hex_hash = sha1.final();
            std::string info_hash_raw = hex_hash;
            std::vector<std::string> peers = get_peers(tracker_url, info_hash_raw, length);
            for (const auto& peer : peers) {
                std::cout << peer << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error querying tracker: " << e.what() << std::endl;
            return 1;
        }
    } else if (command == "handshake") {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " handshake <torrent_file> <peer_ip>:<peer_port>" << std::endl;
            return 1;
        }
        try {
            std::string file_path = argv[2];
            std::string peer_ip_port = argv[3];
            std::string received_peer_id;
            int sock = perform_handshake(file_path, peer_ip_port, received_peer_id);
            std::stringstream ss;
            for (unsigned char c : received_peer_id) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
            }
            std::cout << "Peer ID: " << ss.str() << std::endl;
            close(sock);
        } catch (const std::exception& e) {
            std::cerr << "Error performing handshake: " << e.what() << std::endl;
            return 1;
        }
    } else if (command == "download_piece") {
        if (argc < 6 || std::string(argv[2]) != "-o") {
            std::cerr << "Usage: " << argv[0] << " download_piece -o <output_file> <torrent_file> <piece_index>" << std::endl;
            return 1;
        }
        std::string output_path = argv[3];
        std::string file_path = argv[4];
        int piece_index = std::stoi(argv[5]);
        try {
            download_piece(file_path, output_path, piece_index);
            std::cout << "Piece " << piece_index << " downloaded to " << output_path << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error downloading piece: " << e.what() << std::endl;
            return 1;
        }
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}