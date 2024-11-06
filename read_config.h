#pragma once
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <algorithm>
#include "config_data.h" // The header created by xxd

// Function to trim whitespace from a string (helper function)
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

// Function to read configuration from an embedded string into a map
std::map<std::string, std::string> readConfigFromString(const std::string& configString) {
    std::map<std::string, std::string> config;
    std::istringstream stream(configString);
    std::string line;

    while (std::getline(stream, line)) {
        // Ignore comments and empty lines
        if (line.empty() || line[0] == '#') continue;

        std::istringstream is_line(line);
        std::string key;
        if (std::getline(is_line, key, '=')) {
            std::string value;
            if (std::getline(is_line, value)) {
                key = trim(key);
                value = trim(value);
                config[key] = value;
            }
        }
    }

    return config;
}
