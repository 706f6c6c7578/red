package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"io"
	"os"
)

func main() {
	// Define command-line flags
	passwordFlag := flag.String("p", "", "Password for Argon2id hashing.")
	saltFlag := flag.String("s", "", "Salt for Argon2id hashing.")

	// Set up a usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	// Parse the command-line flags
	flag.Parse()

	// Check for required flags
	if *passwordFlag == "" || *saltFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Generate the key with Argon2id
	key := argon2.IDKey([]byte(*passwordFlag), []byte(*saltFlag), 1, 64*1024, 4, 32)

	// Use the resulting key as a seed to generate an Ed25519 key pair
	seed := sha256.Sum256(key)
	r := hkdf.New(sha256.New, seed[:], nil, nil)
	pubKey, privKey, _ := ed25519.GenerateKey(io.Reader(r))

	// Output the resulting Ed25519 key pair in hex notation
	fmt.Println("Public Key:", hex.EncodeToString(pubKey))
	fmt.Println("Private Key:", hex.EncodeToString(privKey))
}

