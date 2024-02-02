package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"
)

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for one year

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Your Organization"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEMBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM}

	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(keyPEMBlock))
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

func main() {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatal("Failed to generate self-signed certificate: ", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Fatal("Failed to create listener: ", err)
	}
	defer ln.Close()

	fmt.Println("Server listening on :443")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("Accepted connection from %s", conn.RemoteAddr())

	// Create a TLS connection
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Println("Not a TLS connection")
		return
	}

	// Perform the TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		log.Println("TLS handshake error:", err)
		return
	}

	log.Println("TLS handshake successful. Ready to receive data.")

	// Create a buffer for reading data
	buf := make([]byte, 1024)

	for {
		// Read data from the client
		n, err := tlsConn.Read(buf)
		if err != nil {
			log.Println("Read error:", err)
			break
		}

		// Process the received data (in this example, just echo it back)
		receivedData := buf[:n]
		log.Printf("Received data: %s", receivedData)

		// Echo the data back to the client
		_, err = tlsConn.Write(receivedData)
		if err != nil {
			log.Println("Write error:", err)
			break
		}
	}

	log.Printf("Connection from %s closed.", conn.RemoteAddr())
}
