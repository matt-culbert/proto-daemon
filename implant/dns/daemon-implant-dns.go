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
	parts := strings.Split(ip, ".")
	for i := 0; i < len(parts)/2; i++ {
		parts[i], parts[len(parts)-i-1] = parts[len(parts)-i-1], parts[i]
	}
	return fmt.Sprintf("%s.ip6.arpa", strings.Join(parts, "."))
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
