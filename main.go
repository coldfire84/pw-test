package main

import (
	"flag"
	"os"
	"log"
)

func main() {

	var password = flag.String("p", "", "plain text password")
	var hashed = flag.String("h", "", "pbkdf2 password hash. use single quotes so $ symbols aren't taken as variables")
	var saltEncoding = flag.String("s", "base64", "salt encoding to use in password comparison, defaults to base64")

	flag.Parse()

	if HashCompare(*password, *hashed, *saltEncoding) {
		log.Println("Success: plain and hashed passwords match!")
		return
	}
	log.Println("Error: plain and hashed passwords don't match")
	os.Exit(1)
}
