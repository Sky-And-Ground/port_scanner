#pragma once

#include <stdexcept>
#include <fstream>
#include <string>
#include <map>
#include <cctype>

namespace config_parser {
    class FileNotFoundException : public std::runtime_error {
    public:
        FileNotFoundException(const std::string& filePath)
            : std::runtime_error{ "open config file failed: " + filePath }
        {}
    };

    class ConfigParser {
        void process_line(const std::string& line, std::map<std::string, std::string>& resultMap) {
            size_t i = 0;
            size_t keyStart = 0;
            size_t valueStart = 0;
            size_t keyLength = 0;
            size_t valueLength = 0;

            // skip spaces.
            while (i < line.length() && isspace(line[i])) {
                ++i;
            }

            if (i >= line.length()) {
                return;
            }

            // key.
            keyStart = i;

            while (i < line.length() && !isspace(line[i])) {
                ++i;
                ++keyLength;
            }

            if (i >= line.length()) {
                return;
            }

            // check if we has '='
            while (i < line.length() && line[i] != '=') {
                ++i;
            }

            if (i >= line.length()) {
                return;
            }

            // skip spaces.
            ++i;

            while (i < line.length() && isspace(line[i])) {
                ++i;
            }

            if (i >= line.length()) {
                return;
            }

            // value.
            valueStart = i;
            valueLength = line.length() - i;

            i = line.length() - 1;
            while (i > valueStart && isspace(line[i])) {
                --i;
                --valueLength;
            }

            // store the key and value.
            resultMap.emplace(line.substr(keyStart, keyLength), line.substr(valueStart, valueLength));
        }
    public:
        ConfigParser() {}

        std::map<std::string, std::string> parse(const std::string& filePath) {
            std::ifstream in{ filePath };
            if (!in.is_open()) {
                throw FileNotFoundException{ filePath };
            }

            std::map<std::string, std::string> resultMap;
            std::string line;

            while (std::getline(in, line)) {
                if (!line.empty()) {
                    process_line(line, resultMap);
                }
            }

            return resultMap;
        }
    };
}
