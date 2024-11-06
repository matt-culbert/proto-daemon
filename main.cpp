#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <cstring>
#include <string>
#include <map>
#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h> // For uint8_t, uint16_t types
#include "read_config.h"

#pragma comment(lib, "ws2_32.lib") // Link with ws2_32.lib

// Function to build a DNS query packet
std::vector<uint8_t> buildDNSQuery(const std::string& query_name, uint16_t request_type, uint16_t transaction_id) {
    std::vector<uint8_t> packet;

    // Add transaction ID (2 bytes)
    packet.push_back(transaction_id >> 8);
    packet.push_back(transaction_id & 0xFF);

    // Add flags (standard query, recursion desired) (2 bytes)
    packet.push_back(0x01); // QR=0 (query), OPCODE=0, AA=0, TC=0, RD=1
    packet.push_back(0x00); // RA=0, Z=0, RCODE=0

    // QDCOUNT (number of questions) (2 bytes)
    packet.push_back(0x00);
    packet.push_back(0x01); // 1 question

    // ANCOUNT (number of answers) (2 bytes)
    packet.push_back(0x00);
    packet.push_back(0x00);

    // NSCOUNT (number of authority records) (2 bytes)
    packet.push_back(0x00);
    packet.push_back(0x00);

    // ARCOUNT (number of additional records) (2 bytes)
    packet.push_back(0x00);
    packet.push_back(0x00);

    // Add the query name (e.g., "example.com")
    std::istringstream ss(query_name);
    std::string label;
    while (std::getline(ss, label, '.')) {
        packet.push_back(label.size());
        packet.insert(packet.end(), label.begin(), label.end());
    }
    packet.push_back(0x00); // Null terminator for the domain name

    // Add QTYPE (2 bytes)
    packet.push_back(request_type >> 8);
    packet.push_back(request_type & 0xFF);

    // Add QCLASS (2 bytes) - Internet (IN)
    packet.push_back(0x00);
    packet.push_back(0x01);

    return packet;
}

// Function to encode the DNS query packet as a base64 string (for DoH request)
std::string base64Encode(const std::vector<uint8_t>& data) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string encoded;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    return encoded;
}

// Function to send a DoH request using sockets on Windows
void sendDoHRequest(const std::string& dns_server, const std::string& transaction_id) {
    const std::string doh_path = "/";
    const int port = 443;

    // Prepare the HTTP request
    std::ostringstream http_request;
    http_request << "GET " << doh_path << transaction_id << " HTTP/1.1\r\n";
    http_request << "Host: " << dns_server << "\r\n";
    http_request << "Accept: application/dns-message\r\n";
    http_request << "Connection: close\r\n\r\n";

    // Convert the HTTP request to a string
    std::string request_str = http_request.str();

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return;
    }

    // Create a socket
    SOCKET sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == INVALID_SOCKET) {
        std::cerr << "Error creating socket" << std::endl;
        WSACleanup();
        return;
    }

    // Resolve the DNS server address
    struct addrinfo hints, * res;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Use IPv4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(dns_server.c_str(), "5000", &hints, &res) != 0) {
        std::cerr << "Error resolving host: " << dns_server << std::endl;
        closesocket(sockfd);
        WSACleanup();
        return;
    }

    // Connect to the DNS server
    if (connect(sockfd, res->ai_addr, static_cast<int>(res->ai_addrlen)) == SOCKET_ERROR) {
        std::cerr << "Error connecting to the server" << std::endl;
        closesocket(sockfd);
        freeaddrinfo(res);
        WSACleanup();
        return;
    }
    freeaddrinfo(res);

    // Send the HTTP request
    if (send(sockfd, request_str.c_str(), static_cast<int>(request_str.size()), 0) == SOCKET_ERROR) {
        std::cerr << "Error sending request" << std::endl;
        closesocket(sockfd);
        WSACleanup();
        return;
    }

    // Receive the response
    char buffer[1024];
    std::string response;
    int n;
    while ((n = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
    }

    // Close the socket and clean up
    closesocket(sockfd);
    WSACleanup();

    // Print the HTTP response
    std::cout << "Received response:\n" << response << std::endl;
}

int main() {
    // Example of constructing a PTR request for an IPv6 address
    std::string ipv6_address = "2001:0db8::ff00:42:8329"; // Replace with the IPv6 address you want to query
    std::string query_name = "example.com"; // Replace with the domain or reverse IPv6 if doing a PTR request

    // Set the request type (PTR = 0x0C, AAAA = 0x1C)
    uint16_t request_type = 0x1C; // 0x0C = PTR, 0x1C = AAAA

    // Set the transaction ID
    uint16_t transaction_id = 0x1234;

    // Create the DNS request packet
    std::vector<uint8_t> dns_request = buildDNSQuery(query_name, request_type, transaction_id);

    // Encode the DNS query as a base64 string
    std::string query_base64 = base64Encode(dns_request);

    // DoH server address
    std::string doh_server = "localhost";

    std::string transac = "1234";

    // Send the DoH request
    sendDoHRequest(doh_server, transac);

    // Correctly convert the embedded config data into a string
    std::string embeddedConfig(config_txt, config_txt + config_txt_len);

    // Read the configuration into a map
    std::map<std::string, std::string> config = readConfigFromString(embeddedConfig);

    // Example of accessing parameters
    std::string host = config["host"];
    int port = std::stoi(config["port"]);
    int sleep_mil = std::stoi(config["sleep_mil"]);

    // Output the read configuration
    std::cout << "Host: " << host << std::endl;
    std::cout << "Port: " << port << std::endl;
    std::cout << "Sleep time in milliseconds: " << sleep_mil << std::endl;

    return 0;
}
