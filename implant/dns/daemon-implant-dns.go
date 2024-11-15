//go:build dns

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Helper function to format PTR domains
func formatPTR(ip string) string {
	// Expand the IPv6 address to its full representation
	expandedIP := expandIPv6(ip)

	// Remove colons and reverse the characters
	reversed := []rune{}
	for _, char := range expandedIP {
		if char != ':' {
			reversed = append([]rune{char}, reversed...)
		}
	}

	// Join the reversed characters with dots and append ".ip6.arpa"
	return fmt.Sprintf("%s.ip6.arpa", strings.Join(strings.Split(string(reversed), ""), "."))
}

func expandIPv6(ip string) string {
	// Expands an IPv6 address to its full form
	parts := strings.Split(ip, ":")
	var fullParts []string
	for _, part := range parts {
		// Expand each part to 4 digits
		fullParts = append(fullParts, fmt.Sprintf("%04s", part))
	}

	// Join expanded parts
	return strings.Join(fullParts, ":")
}

func main() {
	ip := "2606:4700:4700::1111"
	ptrDomain := formatPTR(ip)

	// Build the DNS packet
	var dnsPacket bytes.Buffer

	// Header
	header := struct {
		ID      uint16
		Flags   uint16
		QDCount uint16
		ANCount uint16
		NSCount uint16
		ARCount uint16
	}{
		ID:      0x04d2, // Random ID
		Flags:   0x0100, // Standard recursive query
		QDCount: 1,      // 1 question
	}
	binary.Write(&dnsPacket, binary.BigEndian, header)

	// Question section: Encode domain name
	labels := strings.Split(ptrDomain, ".")
	for _, label := range labels {
		dnsPacket.WriteByte(byte(len(label)))
		dnsPacket.WriteString(label)
	}
	dnsPacket.WriteByte(0) // End of domain name

	// Type and Class
	question := struct {
		Type  uint16
		Class uint16
	}{
		Type:  12, // PTR
		Class: 1,  // IN
	}
	binary.Write(&dnsPacket, binary.BigEndian, question)

	// Send the packet over HTTPS
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}
	req, err := http.NewRequest("POST", "http://127.0.0.1:8787", &dnsPacket)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making DoH request:", err)
		return
	}
	defer resp.Body.Close()

	// Read and display the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	fmt.Printf("Raw DoH Response: %x\n", body)
}
