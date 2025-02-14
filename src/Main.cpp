#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;
json decode_bencoded_value_helper(const std::string& encoded_value, size_t& pos);

json decode_bencoded_value(const std::string& encoded_value) {
    size_t pos = 0;
    return decode_bencoded_value_helper(encoded_value, pos);
}

json decode_bencoded_value_helper(const std::string& encoded_value, size_t& pos) {
    if (pos >= encoded_value.size()) {
        throw std::runtime_error("Unexpected end of input");
    }

    switch (encoded_value[pos]) {
        case 'i': {
            // Parse integer
            pos++;
            size_t end_pos = encoded_value.find('e', pos);
            if (end_pos == std::string::npos) {
                throw std::runtime_error("Integer does not end with 'e'");
            }
            std::string num_str = encoded_value.substr(pos, end_pos - pos);
            pos = end_pos + 1;

            // Validate integer format
            if (num_str.empty()) {
                throw std::runtime_error("Empty integer");
            }
            if (num_str[0] == '-') {
                if (num_str.size() == 1) {
                    throw std::runtime_error("Invalid integer format: '-' only");
                }
                if (num_str[1] == '0') {
                    throw std::runtime_error("Negative integer with leading zero");
                }
            } else if (num_str[0] == '0' && num_str.size() > 1) {
                throw std::runtime_error("Leading zero in integer");
            }

            try {
                long long num = std::stoll(num_str);
                return json(num);
            } catch (const std::invalid_argument&) {
                throw std::runtime_error("Invalid integer format: " + num_str);
            } catch (const std::out_of_range&) {
                throw std::runtime_error("Integer out of range: " + num_str);
            }
        }
        case 'l': {
            // Parse list
            pos++;
            json list = json::array();
            while (pos < encoded_value.size() && encoded_value[pos] != 'e') {
                json element = decode_bencoded_value_helper(encoded_value, pos);
                list.push_back(element);
            }
            if (pos >= encoded_value.size()) {
                throw std::runtime_error("Unterminated list");
            }
            pos++; // Skip 'e'
            return list;
        }
        case 'd': {
            // Parse dictionary
            pos++;
            json dict = json::object();
            while (pos < encoded_value.size() && encoded_value[pos] != 'e') {
                json key_json = decode_bencoded_value_helper(encoded_value, pos);
                if (!key_json.is_string()) {
                    throw std::runtime_error("Dictionary key is not a string");
                }
                std::string key = key_json.get<std::string>();
                json value = decode_bencoded_value_helper(encoded_value, pos);
                dict[key] = value;
            }
            if (pos >= encoded_value.size()) {
                throw std::runtime_error("Unterminated dictionary");
            }
            pos++; // Skip 'e'
            return dict;
        }
        case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9': {
            // Parse string
            size_t colon_pos = encoded_value.find(':', pos);
            if (colon_pos == std::string::npos) {
                throw std::runtime_error("Colon not found in string length");
            }
            std::string length_str = encoded_value.substr(pos, colon_pos - pos);
            long long length;
            try {
                length = std::stoll(length_str);
            } catch (const std::invalid_argument&) {
                throw std::runtime_error("Invalid string length: " + length_str);
            } catch (const std::out_of_range&) {
                throw std::runtime_error("String length out of range: " + length_str);
            }
            if (length < 0) {
                throw std::runtime_error("Negative string length: " + std::to_string(length));
            }
            pos = colon_pos + 1;
            if (pos + length > encoded_value.size()) {
                throw std::runtime_error("String data exceeds input size");
            }
            std::string str = encoded_value.substr(pos, static_cast<size_t>(length));
            pos += static_cast<size_t>(length);
            return json(str);
        }
        default: {
            throw std::runtime_error("Unexpected character: " + std::string(1, encoded_value[pos]));
        }
    }
}

int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        std::cerr << "Logs from your program will appear here!" << std::endl;

        // Uncomment this block to pass the first stage
         std::string encoded_value = argv[2];
         json decoded_value = decode_bencoded_value(encoded_value);
         std::cout << decoded_value.dump() << std::endl;
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
