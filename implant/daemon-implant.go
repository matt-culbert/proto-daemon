package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Function to reverse an IPv6 address for PTR lookup
func reverseIPv6(ip net.IP) (string, error) {
	ip = ip.To16() // Ensure the address is in 16-byte IPv6 format
	if ip == nil {
		return "", fmt.Errorf("invalid IPv6 address")
	}
	// Reverse each nibble and append ".ip6.arpa" for PTR
	var parts []string
	for i := len(ip) - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x.%x", ip[i]&0xF, ip[i]>>4))
	}
	return strings.Join(parts, ".") + ".ip6.arpa.", nil
}

func main() {
	// IPv6 address to query
	ipStr := "2001:0db8::567:89ab"
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("Invalid IP address: %s", ipStr)
	}

	// Convert IPv6 address to reverse DNS format
	reverseAddr, err := reverseIPv6(ip)
	if err != nil {
		log.Fatalf("Error reversing IP address: %v", err)
	}

	// Build the DNS packet
	var msg dnsmessage.Message
	msg.Header.ID = 12345 // Custom Transaction ID
	msg.Header.RecursionDesired = true
	msg.Questions = []dnsmessage.Question{
		{
			Name:  dnsmessage.MustNewName(reverseAddr),
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		},
	}

	// Marshal the DNS packet
	packet, err := msg.Pack()
	if err != nil {
		log.Fatalf("Failed to pack DNS message: %v", err)
	}

	// Send the DNS packet over UDP
	conn, err := net.Dial("udp", "8.8.8.8:53") // Using Google DNS server
	if err != nil {
		log.Fatalf("Failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	// Send the packet
	_, err = conn.Write(packet)
	if err != nil {
		log.Fatalf("Failed to send DNS packet: %v", err)
	}

	// Receive the response
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	// Unpack and parse the DNS response
	var response dnsmessage.Message
	err = response.Unpack(buffer[:n])
	if err != nil {
		log.Fatalf("Failed to unpack DNS response: %v", err)
	}

	// Print the PTR record from the response
	for _, answer := range response.Answers {
		if answer.Header.Type == dnsmessage.TypePTR {
			fmt.Printf("PTR Record: %s\n", answer.Body.(*dnsmessage.PTRResource).PTR.String())
		}
	}
}
