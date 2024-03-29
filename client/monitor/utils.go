package monitor

import (
	"log"
	"net"
	"os"
)

// getHostname 获取主机名
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Failed to get hostname: %v", err)
		return "unknown"
	}
	return hostname
}

// getHostIP 获取主机的IP地址
func getHostIP() string {
	// 获取所有网络接口
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("Failed to get network interfaces: %v", err)
		return "unknown"
	}

	// 遍历所有地址，寻找非环回（loopback）的IPv4地址
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}

	return "unknown"
}
