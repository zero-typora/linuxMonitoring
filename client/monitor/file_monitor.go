package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

type FileEvent struct {
	Path      string `json:"路径"`
	File      string `json:"文件"`
	Time      string `json:"时间"`
	User      string `json:"用户"`
	Operation string `json:"操作"`
	AlertType string `json:"告警类型"`
	Hostname  string `json:"主机名"`
	IP        string `json:"IP地址"`
}

// addSubDirsToWatcher 递归添加子目录到监控器
func addSubDirsToWatcher(watcher *fsnotify.Watcher, path string) error {
	return filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})
}

// MonitorFile 监控文件改动并发送告警
func MonitorFile(path, serverURL string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("Failed to create watcher:", err)
	}
	defer watcher.Close()
	hostname := getHostname()
	ip := getHostIP()
	// 添加目录及其子目录到监控器
	err = addSubDirsToWatcher(watcher, path)
	if err != nil {
		log.Fatal("Failed to add directories to watcher:", err)
	}

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				currentUser, err := user.Current()
				if err != nil {
					log.Println("获取当前用户失败:", err)
					currentUser = &user.User{Username: "未知"}
				}
				fileEvent := FileEvent{
					Path:      path,
					File:      event.Name,
					Time:      time.Now().Format("2006-01-02-15:04"),
					User:      currentUser.Username,
					Operation: parseOp(event.Op),
					AlertType: "文件操作告警",
					Hostname:  hostname,
					IP:        ip,
				}

				sendAlert(serverURL, fileEvent)

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("监控器错误:", err)
			}
		}
	}()
	<-done
}

// sendAlert 向服务器发送告警
func sendAlert(serverURL string, event FileEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Println("Failed to marshal file event:", err)
		return
	}

	resp, err := http.Post(serverURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Println("Failed to send file event alert:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("File event alert sent successfully")
}

// parseOp 解析文件操作类型
func parseOp(op fsnotify.Op) string {
	switch op {
	case fsnotify.Write:
		return "文件写入"
	case fsnotify.Remove:
		return "文件删除"
	case fsnotify.Rename:
		return "文件重命名"
	case fsnotify.Chmod:
		return "文件权限修改"
	default:
		return "未知操作"
	}
}
