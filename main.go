package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {

	var password = flag.String("p", "", "plain text password")
	var hashed = flag.String("h", "", "pbkdf2 password hash. use single quotes so $ symbols aren't taken as variables")

	flag.Parse()

	if HashCompare(*password, *hashed) {
		fmt.Println("success: plain and hashed passwords match")
		return
	}
	fmt.Println("error: plain and hashed passwords don't match")
	os.Exit(1)
}
