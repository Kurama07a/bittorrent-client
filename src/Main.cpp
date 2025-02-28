/**
 * @file Main.cpp
 * @brief A BitTorrent client implementation in C++.
 * 
 * This file contains the implementation of a BitTorrent client that can decode bencoded values,
 * construct tracker URLs, make HTTP requests to trackers, handle peer communication, and download
 * pieces of a file from peers. The client uses the libcurl library for HTTP requests and OpenSSL
 * for SHA-1 hashing.
 * 
 * Dependencies:
 * - libcurl
 * - OpenSSL
 * - nlohmann/json.hpp
 * 
 * Functions:
 * - binToHex: Converts binary data to a hexadecimal string.
 * - urlEncode: Encodes a URL string.
 * - constructTrackerURL: Constructs a tracker URL with query parameters.
 * - sha1: Computes the SHA-1 hash of a string.
 * - decode_bencoded_value: Decodes a bencoded value.
 * - decode_bencoded_str: Decodes a bencoded string.
 * - decode_bencoded_int: Decodes a bencoded integer.
 * - decode_bencoded_list: Decodes a bencoded list.
 * - decode_bencoded_dict: Decodes a bencoded dictionary.
 * - getIpAddress: Extracts IP addresses from a tracker response.
 * - printResponse: Prints the peer IP addresses from a tracker response.
 * - encode_bencoded_value_dict: Encodes a JSON object as a bencoded dictionary.
 * - readBinaryData: Reads binary data from a file.
 * - decode_bencoded_info: Decodes the "info" dictionary from a torrent file.
 * - WriteCallback: Callback function for writing data received from libcurl.
 * - makeGetRequest: Makes an HTTP GET request using libcurl.
 * - constructUrlFromTorrent: Constructs a tracker URL from a torrent file.
 * - prepareHandShake: Prepares a BitTorrent handshake message.
 * - sendMessage: Sends a message to a peer.
 * - receiveMessage: Receives a message from a peer.
 * - sendInterested: Sends an "interested" message to a peer.
 * - sendRequest: Sends a "request" message to a peer.
 * - verifyPiece: Verifies the integrity of a piece using its SHA-1 hash.
 * - waitForUnchoke: Waits for an "unchoke" message from a peer.
 * - SendRecvHandShake: Sends and receives a BitTorrent handshake with a peer.
 * - downloadPiece: Downloads a specific piece of a file from a peer.
 * - downloadFile: Downloads a file using the provided torrent metadata and saves it to the specified output path.
 * 
 * Main Function:
 * - main: Entry point of the program. Handles command-line arguments and executes the corresponding command.
 * 
 * Usage:
 * - decode <encoded_value>: Decodes a bencoded value and prints the result.
 * - info <torrent>: Prints the information from a torrent file.
 * - peers <torrent>: Prints the peer IP addresses from a tracker response.
 * - handshake <torrent> <peer_ip>:<peerport>: Sends and receives a BitTorrent handshake with a peer.
 * - download_piece -o <output_path> <torrent_file> <piece_index>: Downloads a specific piece of a file from a peer.
 * - download -o <output> <torrent>: Downloads a file using the provided torrent metadata and saves it to the specified output path.
 */
//include headers and libraries , ensure curl / openssl / nlohmann/json.hpp are installed and linked properly 

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


struct Msg
{
    uint32_t length;
    uint8_t id;
} __attribute__((packed));


struct ReqMsg 
{
    uint32_t length;
    uint8_t id;
    uint32_t index;
    uint32_t begin;
    uint32_t length_block;
} __attribute__((packed));


struct info
{
public:
    std::string url;
    size_t length;
    std::string hash;
    size_t pLen;
    std::vector<std::string> pHash;
    std::string binToHex(const std::string &bin)
    void printInfo() const
    {
        std::cout << "Tracker URL: " << url << std::endl;
        std::cout << "Length: " << length << std::endl;
        std::cout << "Info Hash: " << binToHex(hash) << std::endl;
        std::cout << "Piece Length: " << pLen << std::endl;
        std::cout << "Piece Hashes:" << std::endl;
        for (auto it : pHash)
        {
            std::cout << binToHex(it) << std::endl;
        }
    }
};

struct tracker
{
public:
    std::string info_hash;
    size_t peer_id;
    size_t port;
    size_t uploaded;
    size_t downloaded;
    size_t left;
    bool compact;
};

std::string urlEncode(const std::string &url)
{
    char *encoded = curl_easy_escape(nullptr, url.c_str(), url.length());
    std::string res(encoded);
    curl_free(encoded);
    return res;
}


std::string constructTrackerURL(const std::string &trackerUrl,
                                const std::string &inf_hash,
                                const std::string &peerId,
                                int port,
                                int uploaded,
                                int downloaded,
                                int left,
                                int compact)
{
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



std::string sha1(const std::string &inp)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char *>(inp.c_str()), inp.size(), hash);
    return std::string(reinterpret_cast<const char *>(hash), SHA_DIGEST_LENGTH);
}


decoded decode_bencoded_value(const std::string &encoded_value);


decoded decode_bencoded_str(const std::string &str)
{
    size_t colon = str.find(':');
    if (colon != std::string::npos)
    {
        int64_t number = std::stoll(str.substr(0, colon));
        std::string res = str.substr(colon + 1, number);
        return {json(res), number + colon + 1};
    }
    else
    {
        throw std::runtime_error("Invalid encode value: " + str);
    }
}


decoded decode_bencoded_int(const std::string &encoded_value)
{
    size_t pos = encoded_value.find('e');
    if (pos != std::string::npos)
    {
        std::string number_part = encoded_value.substr(1, pos);
        if (number_part == "-0" || (number_part[0] == '0' && number_part.size() < 1) || (number_part[0] == '-' && number_part[1] == '0'))
        {
            throw std::runtime_error("Invalid integer encoding: " + encoded_value);
        }
        long long int val = std::stoll(number_part);
        return {json(val), pos + 1};
    }
    else
    {
        throw std::runtime_error("Invalid encoded value: " + encoded_value);
    }
}


decoded decode_bencoded_list(const std::string &encode_value)
{
    std::string str = encode_value.substr(1);
    json arr = json::array();
    while (str[0] != 'e')
    {
        auto decod = decode_bencoded_value(str);
        arr.push_back(decod.first);
        str = str.substr(decod.second);
    }
    return {arr, encode_value.length() - str.length() + 1};
}


decoded decode_bencoded_dict(const std::string &encode_value)
{
    std::string str = encode_value.substr(1);
    json obj = json::object();
    while (str[0] != 'e')
    {
        // first will be key and it will be always string
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
    return {obj, encode_value.length() - str.length() + 1};
}


decoded decode_bencoded_value(const std::string &encoded_value)
{
    if (std::isdigit(encoded_value[0]))
    {
        // Example: "5:hello" -> "hello"
        return decode_bencoded_str(encoded_value);
    }
    else if (encoded_value[0] == 'i')
    {
        return decode_bencoded_int(encoded_value);
    }
    else if (encoded_value[0] == 'l')
    {
        return decode_bencoded_list(encoded_value);
    }
    else if (encoded_value[0] == 'd')
    {
        return decode_bencoded_dict(encoded_value);
    }
    else
    {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}


std::string getIpAddress(const std::string &resp)
{
    json response = decode_bencoded_value(resp).first;
    std::vector<std::string> ip_ports;
    if (response.contains("peers"))
    {
        auto peers = response.value("peers", "");

        for (int i = 0; i < peers.size(); i += 6)
        {
            unsigned char ipbytes[4];
            std::copy(peers.begin() + i, peers.begin() + i + 4, ipbytes);
            std::string ip = std::to_string(ipbytes[0]) + "." + std::to_string(ipbytes[1]) + "." +
                             std::to_string(ipbytes[2]) + "." + std::to_string(ipbytes[3]);
            unsigned char portbytes[2];
            std::copy(peers.begin() + i + 4, peers.begin() + i + 6, portbytes);
            unsigned short port = (portbytes[0] << 8) + portbytes[1];
            std::string ip_port;
            ip_port += ip;
            ip_port += ":";
            ip_port += std::to_string(port);
            ip_ports.push_back(ip_port);
        }
    }
    else
    {
        std::cout << "does not contain peers" << std::endl;
        return "";
    }
    if (ip_ports.size() > 1)
    {
        return ip_ports[1];
    }
    else
    {
        return ip_ports[0];
    }
}


void printResponse(const std::string &resp)
{
    json response = decode_bencoded_value(resp).first;
    if (response.contains("peers"))
    {
        auto peers = response.value("peers", "");

        for (int i = 0; i < peers.size(); i += 6)
        {
            unsigned char ipbytes[4];
            std::copy(peers.begin() + i, peers.begin() + i + 4, ipbytes);
            std::string ip = std::to_string(ipbytes[0]) + "." + std::to_string(ipbytes[1]) + "." +
                             std::to_string(ipbytes[2]) + "." + std::to_string(ipbytes[3]);
            unsigned char portbytes[2];
            std::copy(peers.begin() + i + 4, peers.begin() + i + 6, portbytes);
            unsigned short port = (portbytes[0] << 8) + portbytes[1];
            std::cout << ip << ":" << port << std::endl;
        }
    }
    else
    {
        std::cout << "does not contain peers" << std::endl;
    }
}


std::string encode_bencoded_value_dict(json &obj)
{
    std::string result;
    for (const auto &item : obj.items())
    {
        auto key = item.key();
        auto length = std::to_string(key.length());
        result += length + ":";
        result += key;
        auto val = item.value();
        if (val.is_number())
        {
            auto num = "i" + val.dump() + "e";
            result += num;
        }
        else if (val.is_string())
        {
            auto str = val.get<std::string>();
            auto len = std::to_string(str.length());
            result += len + ":";
            result += str;
        }
    }
    return result;
}


std::string binToHex(const std::string &bin)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : bin)
    {
        ss << std::setw(2) << static_cast<unsigned>(c);
    }
    return ss.str();
}


std::string readBinaryData(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Error opening the file: " + filename);
    }
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
    file.close();
    return std::string(buffer.begin(), buffer.end());
}


info decode_bencoded_info(const std::string &torrent_file)
{

    info res;
    auto content = readBinaryData(torrent_file);
    auto val = decode_bencoded_value(content).first;
    size_t length;
    std::string url;
    if (val.contains("announce"))
    {
        url = val["announce"];
    }
    if (val.contains("info") && val["info"].is_object())
    {
        auto &info = val["info"];
        if (info.contains("length"))
        {
            length = info["length"];
        }
        std::string encode_bencode = "d";
        encode_bencode += encode_bencoded_value_dict(info);
        encode_bencode += "e";
        auto hash = sha1(encode_bencode);
        res.hash = hash;
        // pieces
        size_t plen = info["piece length"];
        res.pLen = plen;
        auto hashes = info["pieces"];
        if (hashes.is_string())
        {
            auto str = hashes.get<std::string>();
            for (int i = 0; i < str.size(); i += 20)
            {
                std::string chunk = str.substr(i, 20);
                std::string hexChunk = binToHex(chunk);
                res.pHash.push_back(chunk);
            }
        }
    }
    res.url = url;
    res.length = length;
    return res;
}


size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::vector<char> *buffer)
{
    size_t newLength = size * nmemb;
    buffer->insert(buffer->end(), (char *)contents, (char *)contents + newLength);
    return newLength;
}


std::string makeGetRequest(const std::string &url)
{
    CURL *curl = curl_easy_init();
    std::string response;
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        // Follow redirects
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        std::vector<char> responseBuffer;
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }
        else
        {
            response.assign(responseBuffer.begin(), responseBuffer.end());
            // std::cout << "Response: " << response << std::endl;
        }
        curl_easy_cleanup(curl);
    }
    return response;
}


std::string constructUrlFromTorrent(const std::string &filename)
{
    auto info = decode_bencoded_info(filename);
    int port = 6881;
    int uploaded = 0;
    int downloaded = 0;
    std::string peerId = "00112233445566778899";
    int left = info.length;
    int compact = 1;
    auto val = constructTrackerURL(info.url, info.hash, peerId,
                                   port, uploaded, downloaded, left, compact);
    return val;
}


void prepareHandShake(std::vector<char> &handShake, std::string hashinfo)
{
    char protocolLength = 19;
    handShake.push_back(protocolLength);
    std::string protocol = "BitTorrent protocol";
    handShake.insert(handShake.end(), protocol.begin(), protocol.end());
    // eight reserved bytes
    for (int i = 0; i < 8; ++i)
    {
        handShake.push_back(0);
    }
    handShake.insert(handShake.end(), hashinfo.begin(), hashinfo.end());
    std::string peerId = "00112233445566778899";
    handShake.insert(handShake.end(), peerId.begin(), peerId.end());
}


int sendMessage(int sock, const std::vector<char> &message)
{
    if (send(sock, message.data(), message.size(), 0) < 0)
    {
        std::cerr << "Failed to send message" << std::endl;
        return 0;
    }
    return 1;
}


std::vector<char> receiveMessage(int sock, size_t length)
{
    std::vector<char> buffer(length);
    recv(sock, buffer.data(), length, 0);
    return buffer;
}


void sendInterested(int sock)
{
    Msg interestedMsg = {htonl(1), 2}; // Length is 1, ID is 2 for interested
    sendMessage(sock, std::vector<char>(reinterpret_cast<char *>(&interestedMsg),
                                        reinterpret_cast<char *>(&interestedMsg) + sizeof(interestedMsg)));
}


void sendRequest(int sock, uint32_t index, uint32_t begin, uint32_t length_block)
{
    ReqMsg reqMsg = {htonl(13), 6, htonl(index), htonl(begin), htonl(length_block)};
    sendMessage(sock, std::vector<char>(reinterpret_cast<char *>(&reqMsg),
                                        reinterpret_cast<char *>(&reqMsg) + sizeof(reqMsg)));
}


bool verifyPiece(const std::string &piece_data, const std::string &expected_hash)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char *>(piece_data.c_str()), piece_data.size(), hash);
    std::string actual_hash(reinterpret_cast<const char *>(hash), SHA_DIGEST_LENGTH);
    return actual_hash == expected_hash;
}


int waitForUnchoke(int sock)
{
    const int bufferSize = 4; // Buffer size for the length prefix of the message
    char buffer[bufferSize];
    while (true)
    {
        // clear buffer
        memset(buffer, 0, bufferSize);
        // receive th elength of the message
        if (recv(sock, buffer, bufferSize, 0) < 0)
        {
            std::cerr << "Error receiving message length" << std::endl;
            break;
        }
        // conver buffer to uint32_t
        uint32_t msgLength = ntohl(*reinterpret_cast<uint32_t *>(buffer));
        if (msgLength == 0)
        {
            // keep-alive
            continue;
        }
        if (msgLength < 1)
        {
            std::cerr << "Invalid message length received" << std::endl;
            break;
        }
        char msgID;
        if (recv(sock, &msgID, 1, 0) < 0)
        {
            std::cerr << "Error receiving message ID" << std::endl;
            break;
        }
        if (msgID == 1)
        {
            std::cout << "Received unchoke message ID " << std::endl;
            return 1;
        }
        else
        {
            // If not an unchoke message, skip the rest of the message
            std::vector<char> dummyBuffer(msgLength - 1);
            if (recv(sock, dummyBuffer.data(), msgLength - 1, 0) < 0)
            {
                std::cerr << "Error receiving the rest of the message" << std::endl;
                break;
            }
        }
    }
    return 0;
}


int SendRecvHandShake(std::string torrent_file, std::string ipaddress, int &sock)
{
    auto info = decode_bencoded_info(torrent_file);
    std::string server_ip;
    int port;
    size_t colon_pos = ipaddress.find(':');
    if (colon_pos == std::string::npos)
    {
        std::cerr << "Invalid format. Use <IP:Port>" << std::endl;
        return 1;
    }
    server_ip = ipaddress.substr(0, colon_pos);
    port = std::stoi(ipaddress.substr(colon_pos + 1));
    // create a socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        std::cerr << "Error creating a socket" << std::endl;
        return 1;
    }
    // Define the server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Invalid address/Address not supported" << std::endl;
        return 1;
    }
    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Connection Failed" << std::endl;
        return 1;
    }
    std::vector<char> handShakeMsg;
    prepareHandShake(handShakeMsg, info.hash);
    // send the handshake
    if (send(sock, handShakeMsg.data(), handShakeMsg.size(), 0) < 0)
    {
        std::cerr << "Failed to send handshake" << std::endl;
        return 1;
    }
    std::vector<char> handShakeResp(handShakeMsg.size());
    if (recv(sock, handShakeResp.data(), handShakeResp.size(), 0) < 0)
    {
        std::cerr << "Failed to recv handshake" << std::endl;
        return 1;
    }
    if (!handShakeResp.empty())
    {
        std::string resp(handShakeResp.end() - 20, handShakeResp.end());
        std::cout << "Peer ID: " << binToHex(resp) << std::endl;
    }
    return 0;
}


void downloadPiece(const std::string &torrent, int piece_index, const std::string &output_path)
{
    int sock = 0;
    auto info = decode_bencoded_info(torrent);
    auto fullUrl = constructUrlFromTorrent(torrent);
    auto response = makeGetRequest(fullUrl);
    auto ip_port = getIpAddress(response);
    // std::cout << "ip:port" << ip_port << std::endl;
    SendRecvHandShake(torrent, ip_port, sock);
    sendInterested(sock);
    waitForUnchoke(sock);
    size_t piece_length = 16384;
    size_t standard_piece_length = info.pLen;
    size_t total_file_size = info.length;
    size_t num_pieces = (total_file_size + standard_piece_length - 1) / standard_piece_length; // Calculate total number of pieces
    // std::cout << "num pieces: " << num_pieces << std::endl;
    std::ofstream outfile(output_path, std::ios::binary);
    // Determine the size of the current piece
    size_t current_piece_size = (piece_index == num_pieces - 1) ? (total_file_size % standard_piece_length) : standard_piece_length;
    if (current_piece_size == 0)
    {
        current_piece_size = standard_piece_length; // Handle case where file size is an exact multiple of piece length
    }
    size_t remaining = current_piece_size; // Remaining data to download for the current piece
    size_t offset = 0;                     // Offset within the piece
    while (remaining > 0)
    {
        size_t block_length = std::min(piece_length, remaining);
        sendRequest(sock, piece_index, offset, block_length);
        // Receiving piece message
        std::vector<char> length_buffer(4);
        int bytes_received = recv(sock, length_buffer.data(), 4, 0);
        if (bytes_received != 4)
        {
            std::cerr << "Error receiving message length or incomplete read: " << bytes_received << std::endl;
            break;
        }
        int total_bytes_received = 0;
        int message_length = ntohl(*reinterpret_cast<int *>(length_buffer.data()));
        // std::cout << "Iteration, remaining: " << remaining << ", block_length: " << block_length << ", message_length: " << message_length << std::endl;
        std::vector<char> message(message_length);
        while (total_bytes_received < message_length)
        {
            bytes_received = recv(sock, message.data() + total_bytes_received, message_length - total_bytes_received, 0);
            // std::cout << "bytes received: " << bytes_received << std::endl;
            if (bytes_received <= 0)
            {
                std::cerr << "Error receiving message or connection closed" << std::endl;
                break;
            }
            total_bytes_received += bytes_received;
        }
        // std::cout << "Total bytes received for this message: " << total_bytes_received << std::endl;

        // std::cout << "Message ID: " << static_cast<int>(message[0]) << std::endl;
        if (message[0] == 7)
        {
            // Extract block data from message
            std::vector<char> received_block(message.begin() + 9, message.end()); // Skip 1 byte of ID, 4 bytes of index, 4 bytes of begin
            outfile.write(received_block.data(), received_block.size());
            // Update remaining and offset
            remaining -= block_length;
            offset += block_length;
            // Check if this was the last block
            if (remaining == 0)
            {
                // std::cout << "Last block received, exiting loop." << std::endl;
                break;
            }
        }
    }
    outfile.close();
    // Verify piece integrity
    std::cout << "Piece " << piece_index << " downloaded to " << output_path << std::endl;
}


void downloadFile(const std::string &torrent, const std::string &output_path)
{
    info info = decode_bencoded_info(torrent);
    size_t num_pieces = info.pHash.size();
    std::ofstream outfile(output_path, std::ios::binary | std::ios::trunc);
    if (!outfile)
    {
        std::cerr << "Failed to open output file: " << output_path << std::endl;
        return;
    }

    auto fullUrl = constructUrlFromTorrent(torrent);
    auto response = makeGetRequest(fullUrl);
    auto ip_port = getIpAddress(response);
    if (ip_port.empty())
    {
        std::cerr << "No peers available." << std::endl;
        return;
    }

    int sock;
    if (SendRecvHandShake(torrent, ip_port, sock) != 0)
    {
        std::cerr << "Failed to connect to peer." << std::endl;
        return;
    }

    sendInterested(sock);
    if (!waitForUnchoke(sock))
    {
        std::cerr << "Failed to get unchoke." << std::endl;
        close(sock);
        return;
    }

    for (size_t piece_index = 0; piece_index < num_pieces; ++piece_index)
    {
        size_t piece_size = (piece_index == num_pieces - 1) ? (info.length % info.pLen) : info.pLen;
        if (piece_size == 0)
            piece_size = info.pLen;

        std::string piece_data;
        size_t downloaded = 0;
        const size_t block_size = 16384;

        while (downloaded < piece_size)
        {
            size_t request_size = std::min(block_size, piece_size - downloaded);
            sendRequest(sock, piece_index, downloaded, request_size);

            std::vector<char> length_buf(4);
            ssize_t received = recv(sock, length_buf.data(), 4, MSG_WAITALL);
            if (received != 4)
            {
                std::cerr << "Error reading message length." << std::endl;
                close(sock);
                return;
            }
            uint32_t msg_length = ntohl(*reinterpret_cast<uint32_t *>(length_buf.data()));

            std::vector<char> msg(msg_length);
            received = recv(sock, msg.data(), msg_length, MSG_WAITALL);
            if (received != msg_length)
            {
                std::cerr << "Error reading message data." << std::endl;
                close(sock);
                return;
            }

            if (msg[0] == 7)
            {
                uint32_t index = ntohl(*reinterpret_cast<uint32_t *>(msg.data() + 1));
                uint32_t begin = ntohl(*reinterpret_cast<uint32_t *>(msg.data() + 5));
                const char *block = msg.data() + 9;
                size_t block_len = msg_length - 9;

                if (index != piece_index || begin != downloaded)
                {
                    std::cerr << "Unexpected block index or offset." << std::endl;
                    close(sock);
                    return;
                }

                piece_data.append(block, block_len);
                downloaded += block_len;
            }
            else
            {
                std::cerr << "Unexpected message ID: " << static_cast<int>(msg[0]) << std::endl;
                close(sock);
                return;
            }
        }

        if (!verifyPiece(piece_data, info.pHash[piece_index]))
        {
            std::cerr << "Piece " << piece_index << " hash mismatch." << std::endl;
            close(sock);
            return;
        }
        outfile.seekp(piece_index * info.pLen);
        outfile.write(piece_data.data(), piece_data.size());
        std::cout << "Piece " << piece_index << " downloaded and verified." << std::endl;
    }

    outfile.close();
    close(sock);
    std::cout << "Downloaded all pieces to " << output_path << std::endl;
}


int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }
    std::string command = argv[1];
    if (command == "decode")
    {
        // Uncomment this block to pass the first stage
        std::string encoded_value = argv[2];
        json decoded_value = decode_bencoded_value(encoded_value).first;
        std::cout << decoded_value.dump() << std::endl;
    }
    else if (command == "info")
    {
        std::string torrent = argv[2];
        info inf = decode_bencoded_info(torrent);
        inf.printInfo();
    }
    else if (command == "peers")
    {
        std::string torrent = argv[2];
        auto fullUrl = constructUrlFromTorrent(torrent);
        auto response = makeGetRequest(fullUrl);
        printResponse(response);
    }
    else if (command == "handshake")
    {
        if (argc < 4)
        {
            std::cerr << "Usage: " << argv[0] << " <command> <torrent> <peer_ip>:<peerport>" << std::endl;
            return 1;
        }
        std::string torrent = argv[2];
        std::string ipaddress = argv[3];
        int sock;
        SendRecvHandShake(torrent, ipaddress, sock);
    }
    else if (command == "download_piece")
    {
        if (argc < 5)
        {
            std::cerr << "Usage: " << argv[0] << " download_piece -o <output_path> <torrent_file> <piece_index>" << std::endl;
            return 1;
        }
        std::string output_path = argv[3]; // Assuming '-o' is argv[2]
        std::string torrent = argv[4];
        int piece_index = std::stoi(argv[5]);
        downloadPiece(torrent, piece_index, output_path);
    }
    else if (command == "download")
    {
        if (argc < 5 || std::string(argv[2]) != "-o")
        {
            std::cerr << "Usage: " << argv[0] << " download -o <output> <torrent>" << std::endl;
            return 1;
        }
        std::string output = argv[3];
        std::string torrent = argv[4];
        downloadFile(torrent, output);
    }
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }
    return 0;
}