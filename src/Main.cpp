#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "lib/nlohmann/json.hpp"
#include "picosha2.h" // Include PicoSHA2 for SHA-1 hashing

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

// Parse torrent file, return tracker_url and length
void parse_torrent(const std::string& file_path) {
    std::string content = read_file(file_path);
    json decoded_torrent = decode_bencoded_value(content);

    // Extract and bencode the info dictionary
    std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);

    // Compute SHA-1 hash using PicoSHA2
    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(bencoded_info.begin(), bencoded_info.end(), hash.begin(), hash.end());

    // Convert hash to hexadecimal string
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : hash) {
        ss << std::setw(2) << static_cast<unsigned>(byte);
    }
    std::string info_hash = ss.str();

    // Output results
    //std::cout << "Tracker URL: " << decoded_torrent["announce"].get<std::string>() << std::endl;
    //std::cout << "Length: " << decoded_torrent["info"]["length"].get<int>() << std::endl;
    std::cout << "Info Hash: " << info_hash << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value> | info <torrent_file>" << std::endl;
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
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}