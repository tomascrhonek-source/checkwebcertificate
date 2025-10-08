package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"time"
)

func main() {
	flag.Parse()

	addr := flag.Args()[0]

	// Connect to a TLS server
	log.Println("Connecting to:", addr)
	conn, err := tls.Dial("tcp", addr+":443", nil)
	if errors.As(err, &x509.UnknownAuthorityError{}) {
		log.Println("Unknown Authority Error:", err)
	} else if errors.Is(err, tls.RecordHeaderError{}) {
		log.Println("Record Header Error:", err)
	} else if errors.As(err, &x509.HostnameError{}) {
		log.Println("Hostname Error:", err)
	} else if err != nil {
		log.Println("Other error:", err)
	} else if conn.ConnectionState().PeerCertificates == nil {
		log.Println("No certificates presented by the server")
	}
	if err != nil {
		log.Fatalln("Connection error:", err)
	}
	log.Println("Connected to", conn.RemoteAddr())
	defer conn.Close()
	// Verify that the certificate is for the expected host name
	log.Println("Verifying hostname:", addr)
	err = conn.VerifyHostname(addr)
	if err != nil {
		// Certificate is for different host name
		log.Println("Hostname verification error:", err)
	}
	// Get the certificate chain
	certs := conn.ConnectionState().PeerCertificates

	// Extract and print the expiry date of the first certificate
	if len(certs) > 0 {
		cert := certs[0]
		certDate := cert.NotAfter
		days := time.Until(certDate)
		log.Printf("Certificate for %s expires on: %s\n", addr, certDate.Format("2006-01-02 15:04:05"))
		log.Printf("Which is after %.0f days\n", days.Hours()/24)
	} else {
		log.Println("No certificates found.")
	}

}

// t.In(tz).Format("2006-01-02T15:04:05
