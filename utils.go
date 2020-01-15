package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"log"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

/*
* PBKDF2 passwords usage taken from github.com/brocaar/lora-app-server, comments included.
 */

// Generate the hash of a password for storage in the database.
// NOTE: We store the details of the hashing algorithm with the hash itself,
// making it easy to recreate the hash for password checking, even if we change
// the default criteria here.
// Taken from brocaar's lora-app-server: https://github.com/brocaar/lora-app-server
func Hash(password string, saltSize int, iterations int, algorithm string) (string, error) {
	// Generate a random salt value, 128 bits.
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", errors.Wrap(err, "read random bytes error")
	}

	return hashWithSalt(password, salt, iterations, algorithm), nil
}

// Taken from brocaar's lora-app-server: https://github.com/brocaar/lora-app-server
func hashWithSalt(password string, salt []byte, iterations int, algorithm string, saltEncoding string) string {
	// Generate the hash.  This should be a little painful, adjust ITERATIONS
	// if it needs performance tweeking.  Greatly depends on the hardware.
	// NOTE: We store these details with the returned hash, so changes will not
	// affect our ability to do password compares.
	shaSize := sha512.Size
	shaHash := sha512.New
	if algorithm == "sha256" {
		shaSize = sha256.Size
		shaHash = sha256.New
	}
	hash := pbkdf2.Key([]byte(password), salt, iterations, shaSize, shaHash)

	// Build up the parameters and hash into a single string so we can compare
	// other string to the same hash.  Note that the hash algorithm is hard-
	// coded here, as it is above.  Introducing alternate encodings must support
	// old encodings as well, and build this string appropriately.
	var buffer bytes.Buffer

	buffer.WriteString("PBKDF2$")
	buffer.WriteString(fmt.Sprintf("%s$", algorithm))
	buffer.WriteString(strconv.Itoa(iterations))
	buffer.WriteString("$")
	if saltEncoding == "utf-8" {
		buffer.WriteString(string(salt))

	} else {
		buffer.WriteString(base64.StdEncoding.EncodeToString(salt))
	}
	buffer.WriteString("$")
	buffer.WriteString(base64.StdEncoding.EncodeToString(hash))
	log.Println(buffer.String())
	return buffer.String()
}

// HashCompare verifies that passed password hashes to the same value as the
// passed passwordHash.
// Taken from brocaar's lora-app-server: https://github.com/brocaar/lora-app-server
func HashCompare(password string, passwordHash string, saltEncoding string) bool {
	log.Println(passwordHash)
	// SPlit the hash string into its parts.
	hashSplit := strings.Split(passwordHash, "$")
	// Get the iterations from PBKDF2 string
	iterations, _ := strconv.Atoi(hashSplit[2])
	// Encode salt, using encoding supplied in saltEncoding param
	salt := []byte{}
	if saltEncoding == "utf-8" {
		salt = []byte(hashSplit[3])
	} else {
		salt, _ = base64.StdEncoding.DecodeString(hashSplit[3])
	}
	// Get the algorithm from PBKDF2 string
	algorithm := hashSplit[1]
	// Generate new PBKDF2 hash to compare supplied PBKDF2 string against
	newHash := hashWithSalt(password, salt, iterations, algorithm, saltEncoding)
	return newHash == passwordHash
}