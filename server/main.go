package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

// printAlertWithRed 打印带有红色"[+]"前缀的告警信息
func printAlertWithRed(alert string) {
	const red = "\033[31m"
	const reset = "\033[0m"
	fmt.Printf("%s[+] %s%s\n", red, alert, reset)
}

func alertHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	printAlertWithRed(string(body))
}

func main() {
	http.HandleFunc("/alert", alertHandler)
	fmt.Println("Server listening on port 8080...")
	http.ListenAndServe(":8080", nil)
}
