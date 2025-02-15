#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <curl/curl.h> // For making HTTP requests
#include <random> // For generating random peer ID
#include <cstring> // For memcpy
#include <sys/socket.h> // For socket programming
#include <arpa/inet.h> // For inet_addr
#include <unistd.h> // For close()
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
void query_tracker(const std::string& tracker_url, const std::string& info_hash, int file_length);
std:: string perform_handshake(const std::string& file_path, const std::string& peer_ip_port);
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

// Decodes the value based on the current index pointing character
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

// Decodes a bencoded integer
json decode_integer(const std::string& encoded_value, size_t& index) {
    size_t start = index + 1; // skip 'i'
    size_t end = encoded_value.find('e', start);
    if (end == std::string::npos) {
        throw std::runtime_error("Invalid integer encoding.");
    }
    std::string num_str = encoded_value.substr(start, end - start);
    int64_t num = std::atoll(num_str.c_str());
    index = end + 1; // move past 'e'
    return json(num);
}

// Decodes a bencoded string
json decode_string(const std::string& encoded_value, size_t& index) {
    size_t colon = encoded_value.find(':', index);
    if (colon == std::string::npos) {
        throw std::runtime_error("Invalid string encoding.");
    }
    int length = std::stoi(encoded_value.substr(index, colon - index));
    std::string result = encoded_value.substr(colon + 1, length);
    index = colon + 1 + length; // move past the string
    return json(result);
}

// Decodes a bencoded list
json decode_list(const std::string& encoded_value, size_t& index) {
    index++; // skip 'l'
    std::vector<json> list;
    while (index < encoded_value.length() && encoded_value[index] != 'e') {
        list.push_back(decode_value(encoded_value, index));
    }
    index++; // skip 'e'
    return json(list);
}

// Decodes a bencoded dictionary
json decode_dictionary(const std::string& encoded_value, size_t& index) {
    index++; // skip 'd'
    json dict = json::object();
    while (index < encoded_value.length() && encoded_value[index] != 'e') {
        json key = decode_string(encoded_value, index);
        json value = decode_value(encoded_value, index);
        dict[key.get<std::string>()] = value;
    }
    index++; // skip 'e'
    return dict;
}

// Entry point for parsing
json decode_bencoded_value(const std::string& encoded_value) {
    size_t index = 0;
    return decode_value(encoded_value, index);
}

// Read entire content of a file into a string
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

// Convert JSON to bencoded string
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

// Parse torrent file, return tracker_url, length, piece length, and piece hashes
void parse_torrent(const std::string& file_path) {
    std::string content = read_file(file_path);
    json decoded_torrent = decode_bencoded_value(content);

    // Extract and bencode the info dictionary
    std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);

    // Compute SHA-1 hash of the info dictionary
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string info_hash = sha1.final();

    // Extract tracker URL, length, piece length, and piece hashes
    std::string tracker_url = decoded_torrent["announce"];
    int length = decoded_torrent["info"]["length"];
    int piece_length = decoded_torrent["info"]["piece length"];
    std::string pieces = decoded_torrent["info"]["pieces"];

    // Print the required information
    std::cout << "Tracker URL: " << tracker_url << std::endl;
    std::cout << "Length: " << length << std::endl;
    std::cout << "Info Hash: " << info_hash << std::endl;
    std::cout << "Piece Length: " << piece_length << std::endl;
    std::cout << "Piece Hashes: " << std::endl;

    // Split the concatenated piece hashes into individual 20-byte hashes
    for (size_t i = 0; i < pieces.size(); i += 20) {
        std::string piece_hash = pieces.substr(i, 20);
        std::stringstream ss;
        for (unsigned char byte : piece_hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << ss.str() << std::endl;
    }
}

// Callback function for writing HTTP response data
size_t write_callback(void* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append((char*)ptr, size * nmemb);
    return size * nmemb;
}

// Query the tracker and extract peer information
void query_tracker(const std::string& tracker_url, const std::string& info_hash, int file_length) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL.");
    }

    // Prepare query parameters
    std::string peer_id = "82990646878115623196"; // Arbitrary peer ID
    std::string port = "6881"; // Default port
    std::string uploaded = "0"; // No data uploaded yet
    std::string downloaded = "0"; // No data downloaded yet
    std::string left = std::to_string(file_length); // Bytes left to download
    std::string compact = "1"; // Use compact peer list

    // URL encode the info hash
    char* encoded_info_hash = curl_easy_escape(curl, info_hash.c_str(), info_hash.size());
    if (!encoded_info_hash) {
        throw std::runtime_error("Failed to URL encode info hash.");
    }

    // Build the full tracker URL with query parameters
    std::string full_url = tracker_url + "?info_hash=" + encoded_info_hash +
                           "&peer_id=" + peer_id +
                           "&port=" + port +
                           "&uploaded=" + uploaded +
                           "&downloaded=" + downloaded +
                           "&left=" + left +
                           "&compact=" + compact;

    // Set up CURL options
    std::string response_data;
    curl_easy_setopt(curl, CURLOPT_URL, full_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

    // Perform the HTTP GET request
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_free(encoded_info_hash);
        curl_easy_cleanup(curl);
        throw std::runtime_error("Failed to query tracker: " + std::string(curl_easy_strerror(res)));
    }

    // Clean up
    curl_free(encoded_info_hash);
    curl_easy_cleanup(curl);

    // Decode the tracker's response
    json tracker_response = decode_bencoded_value(response_data);

    // Extract the compact peer list
    std::string peers = tracker_response["peers"];

    // Decode the peer list (6 bytes per peer: 4 bytes IP, 2 bytes port)
    for (size_t i = 0; i < peers.size(); i += 6) {
        std::string peer = peers.substr(i, 6);
        std::string ip = std::to_string((unsigned char)peer[0]) + "." +
                         std::to_string((unsigned char)peer[1]) + "." +
                         std::to_string((unsigned char)peer[2]) + "." +
                         std::to_string((unsigned char)peer[3]);
        int port = (unsigned char)peer[4] * 256 + (unsigned char)peer[5];
        std::cout << ip << ":" << port << std::endl;
    }
}

std:: string perform_handshake(const std::string& file_path, const std::string& peer_ip_port) {
    // Parse the torrent file to get the info hash
    std::string content = read_file(file_path);
    json decoded_torrent = decode_bencoded_value(content);
    std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string hex_hash = sha1.final();

    // Convert hex hash to raw bytes
    std::string info_hash_raw;
    for (size_t i = 0; i < hex_hash.size(); i += 2) {
        std::string byte_str = hex_hash.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
        info_hash_raw.push_back(byte);
    }

    // Generate a random peer ID
    std::string peer_id = generate_peer_id();

    // Parse peer IP and port
    size_t colon_pos = peer_ip_port.find(':');
    if (colon_pos == std::string::npos) {
        throw std::runtime_error("Invalid peer IP:port format.");
    }
    std::string peer_ip = peer_ip_port.substr(0, colon_pos);
    int peer_port = std::stoi(peer_ip_port.substr(colon_pos + 1));

    // Create a TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        throw std::runtime_error("Failed to create socket.");
    }

    // Set up the peer address
    struct sockaddr_in peer_addr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    if (inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr) <= 0) {
        close(sock);
        throw std::runtime_error("Invalid peer IP address.");
    }

    // Connect to the peer
    if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        close(sock);
        throw std::runtime_error("Failed to connect to peer.");
    }

    // Prepare the handshake message
    std::string handshake;
    handshake.push_back(19); // Length of "BitTorrent protocol"
    handshake += "BitTorrent protocol"; // Protocol string
    handshake += std::string(8, '\0'); // 8 reserved bytes
    handshake += info_hash_raw; // Info hash
    handshake += peer_id; // Peer ID

    // Send the handshake message
    if (send(sock, handshake.c_str(), handshake.size(), 0) < 0) {
        close(sock);
        throw std::runtime_error("Failed to send handshake.");
    }

    // Receive the handshake response
    char buffer[68]; // 1 + 19 + 8 + 20 + 20 = 68 bytes
    if (recv(sock, buffer, sizeof(buffer), 0) < 0) {
        close(sock);
        throw std::runtime_error("Failed to receive handshake response.");
    }

    // Extract the peer ID from the response
    std::string received_peer_id(buffer + 48, 20); // Peer ID starts at byte 48

    // Print the peer ID in hexadecimal
    

    // Close the socket
    close(sock);
    return received_peer_id;
}

void download_piece(const std::string& file_path, const std::string& output_path, int piece_index) {
    // Parse the torrent file to get the info hash
    std::string content = read_file(file_path);
    json decoded_torrent = decode_bencoded_value(content);
    std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string hex_hash = sha1.final();

    // Convert hex hash to raw bytes
    std::string info_hash_raw;
    for (size_t i = 0; i < hex_hash.size(); i += 2) {
        std::string byte_str = hex_hash.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
        info_hash_raw.push_back(byte);
    }
    
    int piece_length = decoded_torrent["info"]["piece length"];
    std::string pieces = decoded_torrent["info"]["pieces"];

    std:: string tracker_url = decoded_torrent["announce"];
    int file_length = decoded_torrent["info"]["length"];
    query_tracker(tracker_url, info_hash_raw, file_length);

    std:: string peer_ip_port = "127.0.0.0:6881";
    std:: string peer_id = perform_handshake(file_path, peer_ip_port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        throw std::runtime_error("Failed to create socket.");
    }

    struct sockaddr_in peer_addr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(6881);
    if (inet_pton(AF_INET, "127.0.0.1", &peer_addr.sin_addr) <= 0) {
        close(sock);
        throw std::runtime_error("Invalid peer IP address.");
    }
    if(connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        close(sock);
        throw std::runtime_error("Failed to connect to peer.");
    }
    //send interested message
    std::string interested_message = "\x00\x00\x00\x01\x02";
    if (send(sock, interested_message.c_str(), interested_message.size(), 0) < 0) {
        close(sock);
        throw std::runtime_error("Failed to send interested message.");
    }
    //wait for unchoke message
    char unchoke_buffer[5];
    if (recv(sock, unchoke_buffer, sizeof(unchoke_buffer), 0) < 0) {
        close(sock);
        throw std::runtime_error("Failed to receive unchoke message.");
    }
    //request blocks for the piece
    std:: string piece_data;
    int block_size = 16*1024;
    int num_blocks = (piece_length + block_size-1) / block_size;

    for(int block_index =0; block_index<num_blocks; block_index++) {
        int begin = block_index * block_size;
        int length = std::min(piece_length - begin, block_size);
        //prepare request message
        std::string request_message;
        request_message.push_back('\x00');
        request_message.push_back('\x00');
        request_message.push_back('\x00');
        request_message.push_back('\x0D');
        request_message.push_back('\x06');
        request_message.append(reinterpret_cast<char*>(&piece_index), sizeof(piece_index));
        request_message.append(reinterpret_cast<char*>(&begin), sizeof(begin));
        request_message.append(reinterpret_cast<char*>(&length), sizeof(length));

        //send request message
        if (send(sock, request_message.c_str(), request_message.size(), 0) < 0) {
            close(sock);
            throw std::runtime_error("Failed to send request message.");
        }
        //receive the message
        char piece_header[13];
        if (recv(sock, piece_header, sizeof(piece_header), 0) < 0) {
            close(sock);
            throw std::runtime_error("Failed to receive piece header.");
        }
        int received_index = *reinterpret_cast<int*>(piece_header+1);
        int received_begin = *reinterpret_cast<int*>(piece_header+5);

        char block_data[length];
        if (recv(sock, block_data, length, 0) < 0) {
            close(sock);
            throw std::runtime_error("Failed to receive block data.");
        }
        piece_data.append(block_data, length);

        SHA1 piece_sha1;
        piece_sha1.update(piece_data);
        std::string piece_hash = piece_sha1.final();

        std::string expected_hash = pieces.substr(piece_index*20, 20);
        if (piece_hash!= expected_hash){
            close(sock);
            throw std::runtime_error("Piece hash does not match.");
        }

        std::ofstream output_file(output_path, std::ios::binary);
        if(!output_file) {
            close(sock);
            throw std::runtime_error("Failed to open output file.");
        }
        output_file.write(piece_data.c_str(), piece_data.size());
        output_file.close();

        close(sock);
        std::cout << "Piece downloaded successfully." << std::endl;
    }

}    

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value> | info <torrent_file> | peers <torrent_file> | handshake <torrent_file> <peer_ip>:<peer_port> | download_piece -o <output_path> <torrent_file> <piece_index>" << std::endl;
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
            std::string file_path = argv[2];
            parse_torrent(file_path);
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
            std::string file_path = argv[2];
            std::string content = read_file(file_path);
            json decoded_torrent = decode_bencoded_value(content);
            std::string tracker_url = decoded_torrent["announce"];
            int length = decoded_torrent["info"]["length"];
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
            query_tracker(tracker_url, info_hash_raw, length);
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
            std::string peer_id = perform_handshake(file_path, peer_ip_port);
            std::cout << "Peer ID: ";
            for (unsigned char byte : peer_id) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            std::cout << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error performing handshake: " << e.what() << std::endl;
            return 1;
        }
    } else if (command == "download_piece") {
        if (argc < 6 || std::string(argv[2]) != "-o") {
            std::cerr << "Usage: " << argv[0] << " download_piece -o <output_path> <torrent_file> <piece_index>" << std::endl;
            return 1;
        }
        try {
            std::string output_path = argv[3];
            std::string file_path = argv[4];
            int piece_index = std::stoi(argv[5]);
            download_piece(file_path, output_path, piece_index);
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