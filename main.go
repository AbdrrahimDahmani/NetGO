package main

import (
	"crypto/tls"
	"encoding/binary"
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
	IsCIDR      bool
}

// Result holds the scan result for a specific port
type PortResult struct {
	Port    int
	State   string
	Service string
	Banner  string
}

// HostResult holds the result for host discovery
type HostResult struct {
	IP     string
	Status string
}

func main() {
	// 1. Parse Command Line Arguments
	targetPtr := flag.String("target", "127.0.0.1", "Target IP (e.g., 192.168.1.1) or CIDR (e.g., 192.168.1.0/24)")
	rangePtr := flag.String("ports", "1-1024", "Port range for Port Scan Mode (e.g., 1-65535)")
	threadsPtr := flag.Int("threads", 100, "Number of concurrent workers")
	timeoutPtr := flag.Int("timeout", 1000, "Timeout in milliseconds") // Reduced default for faster host discovery
	flag.Parse()

	// 2. Determine Mode (Host Discovery vs Port Scan)
	isCIDR := strings.Contains(*targetPtr, "/")

	config := Config{
		Target:  *targetPtr,
		Threads: *threadsPtr,
		Timeout: time.Duration(*timeoutPtr) * time.Millisecond,
		IsCIDR:  isCIDR,
	}

	if config.IsCIDR {
		runHostDiscovery(config)
	} else {
		// Process Port Range only for Port Scan mode
		start, end, err := parsePortRange(*rangePtr)
		if err != nil {
			fmt.Printf("Error parsing port range: %v\n", err)
			return
		}
		config.StartPort = start
		config.EndPort = end
		runPortScan(config)
	}
}

// --- HOST DISCOVERY LOGIC ---

func runHostDiscovery(config Config) {
	fmt.Printf("\nStarting Host Discovery against Subnet: %s\n", config.Target)
	fmt.Printf("Strategy: TCP Probe on common ports (No Root Required)\n\n")

	ips, err := hostsFromCIDR(config.Target)
	if err != nil {
		fmt.Printf("Error parsing CIDR: %v\n", err)
		return
	}

	ipChan := make(chan string, config.Threads)
	results := make(chan string)
	var wg sync.WaitGroup

	// Start Workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go hostWorker(ipChan, results, &wg, config.Timeout)
	}

	// Feed IPs
	go func() {
		for _, ip := range ips {
			ipChan <- ip
		}
		close(ipChan)
	}()

	// Close results when done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect Results
	var aliveHosts []string
	for ip := range results {
		aliveHosts = append(aliveHosts, ip)
		fmt.Printf("[+] Host Up: %s\n", ip)
	}

	fmt.Printf("\n--- Discovery Complete ---\n")
	fmt.Printf("Found %d live hosts.\n", len(aliveHosts))
}

func hostWorker(ips <-chan string, results chan<- string, wg *sync.WaitGroup, timeout time.Duration) {
	defer wg.Done()
	// Common ports to check for host availability (Ping Scan equivalent)
	commonPorts := []int{80, 443, 22, 445, 135, 3389, 8080}

	for ip := range ips {
		if isHostUp(ip, commonPorts, timeout) {
			results <- ip
		}
	}
}

func isHostUp(ip string, ports []int, timeout time.Duration) bool {
	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			conn.Close()
			return true // Found one open port, host is up
		}
	}
	return false
}

func hostsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// Remove network address and broadcast address (usually first and last)
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// --- PORT SCANNING LOGIC (Existing) ---

func runPortScan(config Config) {
	fmt.Printf("\nStarting Smart Service Scan against %s (%d ports)\n", config.Target, config.EndPort-config.StartPort+1)
	fmt.Printf("Mode: Active Service Detection\n\n")

	ports := make(chan int, config.Threads)
	results := make(chan PortResult)
	var wg sync.WaitGroup

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go portWorker(ports, results, &wg, config)
	}

	go func() {
		for p := config.StartPort; p <= config.EndPort; p++ {
			ports <- p
		}
		close(ports)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var openPorts []PortResult
	for res := range results {
		if res.State == "Open" {
			openPorts = append(openPorts, res)
			fmt.Printf("[+] Port %-5d : %-15s | %s\n", res.Port, res.Service, res.Banner)
		}
	}

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

func portWorker(ports <-chan int, results chan<- PortResult, wg *sync.WaitGroup, config Config) {
	defer wg.Done()
	for port := range ports {
		res := scanPort(config.Target, port, config.Timeout)
		if res.State == "Open" {
			results <- res
		}
	}
}

func scanPort(target string, port int, timeout time.Duration) PortResult {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return PortResult{Port: port, State: "Closed"}
	}
	defer conn.Close()

	service, banner := detectService(conn, target, port, timeout)
	return PortResult{
		Port:    port,
		State:   "Open",
		Service: service,
		Banner:  banner,
	}
}

func detectService(conn net.Conn, target string, port int, timeout time.Duration) (string, string) {
	conn.SetDeadline(time.Now().Add(timeout * 2))

	// 1. Passive Listen
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := conn.Read(buffer)

	var initialResponse string
	if err == nil && n > 0 {
		initialResponse = string(buffer[:n])
		cleanBanner := strings.TrimSpace(strings.ReplaceAll(initialResponse, "\n", " "))
		if len(cleanBanner) > 50 {
			cleanBanner = cleanBanner[:50] + "..."
		}
		if strings.Contains(initialResponse, "SSH") {
			return "SSH", cleanBanner
		}
		if strings.HasPrefix(initialResponse, "220") {
			return "FTP/SMTP", cleanBanner
		}
		return "Unknown (Chatty)", cleanBanner
	}

	// 2. Active Probe (HTTP)
	conn.SetDeadline(time.Now().Add(timeout))
	httpRequest := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", target)
	conn.Write([]byte(httpRequest))
	n, err = conn.Read(buffer)
	if err == nil && n > 0 {
		response := string(buffer[:n])
		if strings.Contains(response, "HTTP/") {
			serverHeader := extractHeader(response, "Server")
			if serverHeader != "" {
				return "HTTP", serverHeader
			}
			return "HTTP", "Web Server"
		}
	}

	// 3. TLS Probe
	address := fmt.Sprintf("%s:%d", target, port)
	tlsConf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", address, tlsConf)
	if err == nil {
		defer tlsConn.Close()
		return "SSL/TLS", "Encrypted Service"
	}

	return "Unknown", "No Banner"
}

func extractHeader(response, headerName string) string {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(headerName)+":") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}

func parsePortRange(rangeStr string) (int, int, error) {
	if strings.Contains(rangeStr, "-") {
		parts := strings.Split(rangeStr, "-")
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("invalid range format")
		}
		return start, end, nil
	}
	p, err := strconv.Atoi(rangeStr)
	return p, p, err
}

// Helper needed for CIDR parsing in some Go versions (generic binary encoding)
func ipToInt(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func intToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}