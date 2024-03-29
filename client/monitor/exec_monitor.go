package monitor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"time"
)

// AlertInfo 结构体定义，用于构造发送到服务器的告警信息
type AlertInfo struct {
	Time      string `json:"time"`
	Command   string `json:"command"`
	TTY       string `json:"tty"`
	UID       string `json:"uid"`
	GID       string `json:"gid"`
	ExecPath  string `json:"execPath"`
	Hostname  string `json:"hostname"`
	HostIP    string `json:"hostIP"`
	AlertType string `json:"alertType"`
}

// sendAlerts 向服务器发送告警信息
func sendAlerts(serverURL string, alert AlertInfo) {
	// 将 AlertInfo 对象序列化为 JSON
	data, err := json.Marshal(alert)
	if err != nil {
		log.Printf("Failed to marshal alert: %v", err)
		return
	}

	// 发送 HTTP POST 请求到服务器
	resp, err := http.Post(serverURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to send alert: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("Alert sent successfully: %s", alert.Command)
}

// MonitorAuditLogs 监控特定关键字的审计日志
func MonitorAuditLogs(serverURL string) {
	keywords := []string{"id_audit", "python3_audit", "whoami_audit", "chmod_audit", "useradd_audit", "sudo_audit", "su_audit"}

	for _, keyword := range keywords {
		go func(kw string) {
			monitorKeywordLogs(serverURL, kw)
		}(keyword)
	}
}

func monitorKeywordLogs(serverURL, keyword string) {
	// 定义正则表达式以解析审计日志的关键信息
	timeRegexp := regexp.MustCompile(`time->(.+)`)
	commRegexp := regexp.MustCompile(`comm="([^"]+)"`)
	uidRegexp := regexp.MustCompile(`uid=([0-9]+)`)
	gidRegexp := regexp.MustCompile(`gid=([0-9]+)`)
	ttyRegexp := regexp.MustCompile(`tty=([^ ]+)`)
	exeRegexp := regexp.MustCompile(`exe="([^"]+)"`)

	var lastEvent AlertInfo
	var lastEventTime string

	hostname := getHostname()
	hostIP := getHostIP()

	for {
		cmd := exec.Command("ausearch", "-k", keyword)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("Error creating StdoutPipe: %v", err)
			continue
		}
		if err := cmd.Start(); err != nil {
			log.Printf("Error starting ausearch command: %v", err)
			continue
		}

		scanner := bufio.NewScanner(stdout)
		var isNewEvent bool
		for scanner.Scan() {
			line := scanner.Text()

			// 从每一行中提取信息
			if timeMatch := timeRegexp.FindStringSubmatch(line); timeMatch != nil {
				if timeMatch[1] > lastEventTime {
					isNewEvent = true
					lastEventTime = timeMatch[1]
					lastEvent.Time = timeMatch[1]
				}
			}
			if commMatch := commRegexp.FindStringSubmatch(line); commMatch != nil {
				lastEvent.Command = commMatch[1]
			}
			if uidMatch := uidRegexp.FindStringSubmatch(line); uidMatch != nil {
				lastEvent.UID = uidMatch[1]
			}
			if gidMatch := gidRegexp.FindStringSubmatch(line); gidMatch != nil {
				lastEvent.GID = gidMatch[1]
			}
			if ttyMatch := ttyRegexp.FindStringSubmatch(line); ttyMatch != nil {
				lastEvent.TTY = ttyMatch[1]
			}
			if exeMatch := exeRegexp.FindStringSubmatch(line); exeMatch != nil {
				lastEvent.ExecPath = exeMatch[1]
			}
			if isNewEvent {
				if uidMatch := uidRegexp.FindStringSubmatch(line); uidMatch != nil {
					lastEvent.UID = uidMatch[1]
				}
			}
		}
		if err := cmd.Wait(); err != nil {
			log.Printf("Error waiting for ausearch command to finish: %v", err)
		}

		// 仅在发现新事件时发送告警
		if isNewEvent {
			log.Println("Sending alert for new event") // 新增的日志
			lastEvent.Hostname = hostname
			lastEvent.HostIP = hostIP
			lastEvent.AlertType = "高危命令执行"
			sendAlerts(serverURL, lastEvent)
			// 重置 isNewEvent 以准备下一次循环
			isNewEvent = false
		}

		// 暂停一段时间再次执行查询，以减少系统负载
		time.Sleep(10 * time.Second)
	}
}
