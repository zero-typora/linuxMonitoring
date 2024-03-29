package monitor

import (
	"bytes"
	"os/exec"
)

// ExecuteCommand 执行给定的系统命令并返回其标准输出。如果命令执行失败，则返回错误。
func ExecuteCommand(command string, args []string) string {
	cmd := exec.Command(command, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "" // 返回错误
	}
	return out.String() // 成功执行，返回输出
}
