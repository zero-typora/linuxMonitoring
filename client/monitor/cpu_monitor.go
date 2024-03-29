package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// CPUUsageInfo 结构体定义
type CPUUsageInfo struct {
	PID         string `json:"pid"`
	ProcessName string `json:"processName"`
	CPUUsage    string `json:"cpuUsage"`
	CommandPath string `json:"commandPath"`
	Cmdline     string `json:"cmdline"`
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	LX          string `json:"CPU告警监控"`
}

// alertedPIDs 用于跟踪已经发送过告警的进程ID
var alertedPIDs = make(map[int32]struct{})

// sendCPUAlert 向服务器发送CPU使用率告警
func sendCPUAlert(serverURL string, event CPUUsageInfo) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal CPU usage event: %v", err)
		return
	}

	log.Printf("Sending CPU usage event: %s\n", string(data)) // 打印即将发送的数据

	resp, err := http.Post(serverURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to send CPU usage event alert: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)                                    // 读取响应体
	log.Printf("Received response: %d - %s", resp.StatusCode, string(body)) // 打印响应状态码和响应体

	if resp.StatusCode != http.StatusOK {
		log.Printf("Unexpected response status: %d", resp.StatusCode)
	} else {
		log.Println("CPU usage event alert sent successfully")
	}
}

// MonitorHighCPUUsage 使用gopsutil库实时循环监控CPU使用率
func MonitorHighCPUUsage(serverURL string) {
	alerted := make(map[string]struct{})

	for {
		// 使用ps命令获取CPU使用率超过10%的进程
		output := ExecuteCommand("bash", []string{"-c", `ps -eo pid,comm,%cpu --sort=-%cpu | awk 'NR>1 && $3 > 70 {print $1 " " $2 " " $3}'`})
		if output == "" {
			time.Sleep(10 * time.Second)
			continue
		}

		processes := strings.Split(output, "\n")
		for _, proc := range processes {
			parts := strings.Fields(proc)
			if len(parts) != 3 {
				continue
			}

			pid := parts[0]
			// 如果该进程已发送过告警，则跳过
			if _, exists := alerted[pid]; exists {
				continue
			}

			cpuInfo := CPUUsageInfo{
				PID:         parts[0],
				ProcessName: parts[1],
				CPUUsage:    parts[2],
				CommandPath: ExecuteCommand("bash", []string{"-c", fmt.Sprintf("readlink -f /proc/%s/exe", pid)}),
				Cmdline:     ExecuteCommand("cat", []string{fmt.Sprintf("/proc/%s/cmdline", pid)}),
				Hostname:    getHostname(),
				IP:          getHostIP(),
				LX:          "CPU异常占用",
			}

			// 使用sendCPUAlert函数发送告警
			sendCPUAlert(serverURL, cpuInfo)

			// 标记该进程已发送告警
			alerted[pid] = struct{}{}
		}

		time.Sleep(10 * time.Second)
	}
}
