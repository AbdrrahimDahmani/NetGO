package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config holds the scanner configuration
type Config struct {
	Target      string
	StartPort   int
	EndPort     int
	Threads     int
	Timeout     time.Duration
	Verbose     bool
}

// Result holds the scan result for a specific port
type Result struct {
	Port    int
	State   string
	Service string
	Banner  string
}

func main() {
	// 1. Parse Command Line Arguments
	targetPtr := flag.String("target", "127.0.0.1", "Target IP or Hostname")
	rangePtr := flag.String("ports", "1-1024", "Port range to scan (e.g., 1-65535)")
	threadsPtr := flag.Int("threads", 100, "Number of concurrent workers")
	timeoutPtr := flag.Int("timeout", 2000, "Timeout per port in milliseconds")
	flag.Parse()

	// 2. Process Port Range
	startPort, endPort, err := parsePortRange(*rangePtr)
	if err != nil {
		fmt.Printf("Error parsing port range: %v\n", err)
		return
	}

	config := Config{
		Target:    *targetPtr,
		StartPort: startPort,
		EndPort:   endPort,
		Threads:   *threadsPtr,
		Timeout:   time.Duration(*timeoutPtr) * time.Millisecond,
	}

	fmt.Printf("\nStarting Smart Scanner against %s (%d ports)\n", config.Target, endPort-startPort+1)
	fmt.Printf("Mode: Active Service Detection\n\n")

	// 3. Set up Concurrency
	ports := make(chan int, config.Threads)
	results := make(chan Result)
	var wg sync.WaitGroup

	// Start Workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(ports, results, &wg, config)
	}

	// Send Ports to Workers
	go func() {
		for p := config.StartPort; p <= config.EndPort; p++ {
			ports <- p
		}
		close(ports)
	}()

	// Close results channel when workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// 4. Collect and Print Results
	var openPorts []Result
	for res := range results {
		if res.State == "Open" {
			openPorts = append(openPorts, res)
			// Live output
			fmt.Printf("[+] Port %-5d : %-15s | %s\n", res.Port, res.Service, res.Banner)
		}
	}

	// Summary
	fmt.Println("\n--- Scan Complete ---")
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})
	
	if len(openPorts) == 0 {
		fmt.Println("No open ports found.")
	} else {
		fmt.Printf("Found %d open ports.\n", len(openPorts))
	}
}

// worker processes ports from the channel
func worker(ports <-chan int, results chan<- Result, wg *sync.WaitGroup, config Config) {
	defer wg.Done()
	for port := range ports {
		res := scanPort(config.Target, port, config.Timeout)
		if res.State == "Open" {
			results <- res
		}
	}
}

// scanPort attempts to connect and detect the service
func scanPort(target string, port int, timeout time.Duration) Result {
	address := fmt.Sprintf("%s:%d", target, port)
	
	// 1. Initial TCP Connect
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return Result{Port: port, State: "Closed"}
	}
	defer conn.Close()

	// If we connected, the port is open. Now we detect the service.
	service, banner := detectService(conn, target, port, timeout)

	return Result{
		Port:    port,
		State:   "Open",
		Service: service,
		Banner:  banner,
	}
}

// detectService performs active probing to identify the protocol
func detectService(conn net.Conn, target string, port int, timeout time.Duration) (string, string) {
	// Set deadlines for I/O
	conn.SetDeadline(time.Now().Add(timeout * 2))

	// Strategy 1: Passive Listen (Banner Grabbing)
	// Many protocols (SSH, FTP, SMTP) send a banner immediately upon connection.
	// We wait briefly to see if the server speaks first.
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) 
	n, err := conn.Read(buffer)
	
	var initialResponse string
	if err == nil && n > 0 {
		initialResponse = string(buffer[:n])
		// Clean up newlines for display
		cleanBanner := strings.TrimSpace(strings.ReplaceAll(initialResponse, "\n", " "))
		if len(cleanBanner) > 50 {
			cleanBanner = cleanBanner[:50] + "..."
		}

		// Check signatures based on initial banner
		if strings.Contains(initialResponse, "SSH") {
			return "SSH", cleanBanner
		}
		if strings.HasPrefix(initialResponse, "220") {
			if strings.Contains(strings.ToLower(initialResponse), "ftp") {
				return "FTP", cleanBanner
			}
			if strings.Contains(strings.ToLower(initialResponse), "smtp") || strings.Contains(initialResponse, "ESMTP") {
				return "SMTP", cleanBanner
			}
			return "FTP/SMTP?", cleanBanner
		}
		if strings.HasPrefix(initialResponse, "RFB") {
			return "VNC", cleanBanner
		}
		// If we got data but don't recognize it, return unknown with the data
		return "Unknown (Chatty)", cleanBanner
	}

	// Strategy 2: Active Probing (Protocol Injection)
	// If the server didn't speak (timeout or EOF), it's likely a "polite" protocol
	// like HTTP, or it expects a specific handshake (TLS).

	// Reset deadline for writing/reading
	conn.SetDeadline(time.Now().Add(timeout))

	// Probe A: Send a generic HTTP HEAD request
	// This is the most common silent service.
	httpRequest := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", target)
	_, err = conn.Write([]byte(httpRequest))
	if err == nil {
		// Try to read response
		n, err = conn.Read(buffer)
		if err == nil && n > 0 {
			response := string(buffer[:n])
			if strings.Contains(response, "HTTP/") {
				// Parse Server header if possible
				serverHeader := extractHeader(response, "Server")
				if serverHeader != "" {
					return "HTTP", serverHeader
				}
				return "HTTP", "Web Server"
			}
		}
	}

	// Strategy 3: TLS/SSL Probe
	// If standard TCP failed to elicit a clear response, try a TLS handshake.
	// We dial a NEW connection for this to ensure a clean state.
	address := fmt.Sprintf("%s:%d", target, port)
	tlsConf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", address, tlsConf)
	if err == nil {
		defer tlsConn.Close()
		// If handshake succeeds, it is an SSL/TLS service (HTTPS, FTPS, IMAPS, etc.)
		// We can try to write HTTP over TLS to see if it's HTTPS
		tlsConn.Write([]byte(httpRequest))
		tlsConn.SetReadDeadline(time.Now().Add(timeout))
		n, err := tlsConn.Read(buffer)
		if err == nil && n > 0 {
			response := string(buffer[:n])
			if strings.Contains(response, "HTTP/") {
				return "HTTPS", "Secure Web Server"
			}
		}
		return "SSL/TLS", "Encrypted Service"
	}

	// Default fallback
	return "Unknown", "No Banner"
}

// Helper to extract headers from HTTP responses
func extractHeader(response, headerName string) string {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(headerName)+":") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}

// Helper to parse "1-100" or "80"
func parsePortRange(rangeStr string) (int, int, error) {
	if strings.Contains(rangeStr, "-") {
		parts := strings.Split(rangeStr, "-")
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("invalid range format")
		}
		if start > end {
			return 0, 0, fmt.Errorf("start port cannot be greater than end port")
		}
		return start, end, nil
	}
	// Single port
	p, err := strconv.Atoi(rangeStr)
	if err != nil {
		return 0, 0, err
	}
	return p, p, nil
}
