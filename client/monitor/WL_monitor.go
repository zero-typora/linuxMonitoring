package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ConnectionEvent 用于存储连接及进程相关信息
type ConnectionEvent struct {
	RemoteIP    string `json:"remoteIP"`
	RemotePort  string `json:"remotePort"`
	PID         string `json:"pid"`
	ProcessPath string `json:"processPath"`
	ProcessName string `json:"processName"`
	IsMalicious string `json:"isMalicious"`
	Hostname    string `json:"hostname"`
	HostIP      string `json:"hostIP"`
	AlertType   string `json:"alertType"`
}

// ThreatbookResponse 定义了从微步API返回的数据结构
type ThreatbookResponse struct {
	Data map[string]struct {
		IsMalicious bool `json:"is_malicious"`
	} `json:"data"`
	ResponseCode int    `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
}

var (
	alerted  sync.Map // 存储已经发送过告警的IP
	firstRun = true   // 标识是否为第一次执行监控
)

// CheckIPMaliciousness 调用微步API检查IP是否为恶意
func CheckIPMaliciousness(ip, apiKey string) (bool, error) {
	// 先检查这个IP是否已经检查过了
	if _, exists := alerted.Load(ip); exists {
		// 如果已经检查过，就不再重复检查
		return false, fmt.Errorf("IP %s 已经检查过并发送过告警", ip)
	}

	// 构造请求URL
	url := fmt.Sprintf("https://api.threatbook.cn/v3/scene/ip_reputation?apikey=%s&resource=%s", apiKey, ip)
	response, err := http.Get(url)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	// 解析返回的JSON数据
	var tbResponse ThreatbookResponse
	err = json.NewDecoder(response.Body).Decode(&tbResponse)
	if err != nil {
		return false, err
	}

	// 检查响应代码，确保请求成功
	if tbResponse.ResponseCode != 0 {
		return false, fmt.Errorf("查询失败，响应代码：%d，信息：%s", tbResponse.ResponseCode, tbResponse.VerboseMsg)
	}

	// 根据API的返回结果，检查IP是否被标记为恶意
	if data, exists := tbResponse.Data[ip]; exists {
		// 直接返回该IP的恶意状态
		return data.IsMalicious, nil
	} else {
		// 如果API没有返回这个IP的信息，我们默认它不是恶意的
		return false, nil
	}
}

// getProcessPathByPID 根据PID获取进程路径
func getProcessPathByPID(pid string) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%s/exe", pid))
	if err != nil {
		return "", err
	}
	return path, nil
}

// getProcessNameByPID 根据PID获取进程名称
func getProcessNameByPID(pid string) (string, error) {
	cmd := fmt.Sprintf("ps -p %s -o comm=", pid)
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// MonitorConnections 检索并解析所有ESTABLISHED状态的外联连接
func MonitorConnections(serverURL, apiKey string) {
	for {
		connections, err := getEstablishedConnections(apiKey)
		if err != nil {
			log.Printf("Failed to get established connections: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		for _, conn := range connections {
			// 对每个连接，检查其是否已经发送过告警
			// 如果是首次运行，或者这个IP之前没有发送过告警，尝试发送告警
			_, alertedBefore := alerted.Load(conn.RemoteIP)
			if firstRun || !alertedBefore {
				sendAlertIfNecessary(serverURL, apiKey, conn)
				// 不论结果如何，标记该IP为已处理，以避免重复发送
				// 注意：这里我们假设你希望在首次运行时发送所有连接的告警，之后只对新发现或者未处理的连接进行处理
				alerted.Store(conn.RemoteIP, struct{}{})
			}
		}

		// 首次运行后，更新firstRun标志
		if firstRun {
			firstRun = false
		}

		time.Sleep(10 * time.Second)
	}
}

func isAlertedBefore(ip string) bool {
	_, exists := alerted.Load(ip)
	return exists
}

func getEstablishedConnections(apiKey string) ([]ConnectionEvent, error) {
	output, err := exec.Command("bash", "-c", "netstat -antp | grep ESTABLISHED").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("executing netstat command: %v", err)
	}

	var connections []ConnectionEvent
	lines := strings.Split(string(output), "\n")
	re := regexp.MustCompile(`tcp\s+\d+\s+\d+\s+\S+\s+(\S+):(\d+)\s+ESTABLISHED\s+(\d+)/(\S+)`)
	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) != 5 {
			continue
		}

		remoteIP, remotePort, pid := matches[1], matches[2], matches[3]
		processPath, err := getProcessPathByPID(pid)
		if err != nil {
			log.Printf("Failed to get process path for PID %s: %v", pid, err)
			continue
		}
		processName, err := getProcessNameByPID(pid)
		if err != nil {
			log.Printf("Failed to get process name for PID %s: %v", pid, err)
			continue
		}
		isMalicious, err := CheckIPMaliciousness(remoteIP, apiKey)
		if err != nil {
			log.Printf("Failed to check if IP %s is malicious: %v", remoteIP, err)
			continue
		}

		hostname, hostIP := getHostname(), getHostIP()

		connection := ConnectionEvent{
			RemoteIP:    remoteIP,
			RemotePort:  remotePort,
			PID:         pid,
			ProcessPath: processPath,
			ProcessName: processName,
			IsMalicious: fmt.Sprintf("%t", isMalicious),
			Hostname:    hostname,
			HostIP:      hostIP,
			AlertType:   "外联IP监控",
		}

		connections = append(connections, connection)
	}

	return connections, nil
}

func sendAlertIfNecessary(serverURL, apiKey string, conn ConnectionEvent) {
	// 始终尝试检查IP的恶意性，即使之前已经检查过
	isMalicious, err := CheckIPMaliciousness(conn.RemoteIP, apiKey)

	// 如果查询失败（不论是因为API限额还是其他原因），记录错误但继续发送告警
	// 注意：这里改为记录错误，而不是终止函数
	if err != nil {
		log.Printf("Attempt to check if IP %s is malicious failed: %v", conn.RemoteIP, err)
		// 这里我们选择在查询失败时默认设置为"否"，因为无法确定其恶意性
		// 如果您希望在查询失败时采取不同的默认行为，可以在这里调整
		conn.IsMalicious = "否"
	} else {
		// 根据IP恶意性决定是否发送告警
		if isMalicious {
			conn.IsMalicious = "是"
		} else {
			conn.IsMalicious = "否"
		}
	}

	// 尝试发送告警信息
	if SendAlert(serverURL, conn) {
		log.Printf("Alert sent successfully for IP: %s, IsMalicious: %s\n", conn.RemoteIP, conn.IsMalicious)
	} else {
		log.Printf("Failed to send alert for IP: %s, IsMalicious: %s\n", conn.RemoteIP, conn.IsMalicious)
	}
}

func SendAlert(serverURL string, event ConnectionEvent) bool {
	jsonData, err := json.Marshal(event)
	if err != nil {
		log.Printf("Error marshalling event to JSON: %v", err)
		return false
	}

	req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending alert: %v", err)
		return false
	}
	defer resp.Body.Close()

	// 确认响应状态码为成功
	if resp.StatusCode == http.StatusOK {
		log.Printf("Alert sent successfully for IP: %s, IsMalicious: %s\n", event.RemoteIP, event.IsMalicious)
		return true
	} else {
		log.Printf("Failed to send alert for IP: %s, status code: %d\n", event.RemoteIP, resp.StatusCode)
		return false
	}
}
