package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	hash := "$2a$10$kC5S1eGUZ5agaDc7WJSmQuQtwJE7.dIYNhXIJr94sINMOFtUBbVAO"
	for _, pw := range []string{"admin123", "admin", "password", "123456", "forensix"} {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil {
			fmt.Println("MATCH:", pw)
			return
		}
	}
	fmt.Println("NO MATCH")
}
