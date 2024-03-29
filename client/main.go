package main

import (
	"log"
	"monitoring_system/client/monitor"
)

func main() {
	cfg, err := LoadConfig("./config.json") // 这应该正常工作，假设config.go在同一包内
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	go monitor.MonitorFile(cfg.MonitorPath, cfg.ServerURL) // 以goroutine运行
	//go monitor.MonitorHighCPUUsage(cfg.ServerURL)
	//go monitor.MonitorAuditLogs(cfg.ServerURL)
	//go monitor.MonitorConnections(cfg.ServerURL, cfg.ThreatBookAPIKey)
	// 防止主goroutine退出
	select {}
}
