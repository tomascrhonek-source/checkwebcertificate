package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().UTC().Format("2006-01-02 15:04:05 ") + string(bytes))
}

func checkCerts(addr string, debug *bool) int {
	var completeAddr string

	if !strings.Contains(addr, ":") {
		completeAddr = fmt.Sprintf("%s:%d", addr, 443)
	} else {
		completeAddr = addr
	}

	addr = strings.Split(completeAddr, ":")[0]

	// Connect to a TLS server
	if *debug {
		log.Println("Connecting to:", completeAddr)
	}
	conn, err := tls.Dial("tcp", completeAddr, nil)
	if errors.As(err, &x509.UnknownAuthorityError{}) {
		log.Println("Unknown Authority Error:", err)
		os.Exit(1)
	} else if errors.Is(err, tls.RecordHeaderError{}) {
		log.Println("Record Header Error:", err)
		os.Exit(1)
	} else if errors.As(err, &x509.HostnameError{}) {
		log.Println("Hostname Error:", err)
		os.Exit(1)
	} else if err != nil {
		log.Println("Other error:", err)
		os.Exit(1)
	} else if conn.ConnectionState().PeerCertificates == nil {
		log.Println("No certificates presented by the server")
		os.Exit(1)
	}
	if err != nil {
		log.Fatalln("Connection error:", err)
		os.Exit(1)
	}

	if *debug {
		log.Println("Connected to", conn.RemoteAddr())
	}
	defer conn.Close()

	// Verify that the certificate is for the expected host name
	if *debug {
		log.Println("Verifying hostname:", addr)
	}
	err = conn.VerifyHostname(addr)
	if err != nil {
		// Certificate is for different host name
		log.Println("Hostname verification error:", err)
		os.Exit(1)
	}

	// Get the certificate chain
	if *debug {
		log.Println("Getting the certificate chain")
	}
	certs := conn.ConnectionState().PeerCertificates

	// Extract and print the expiry date of the first certificate
	if len(certs) > 0 {
		cert := certs[0]
		certDate := cert.NotAfter
		days := time.Until(certDate)
		log.Printf("Certificate for %s expires on: %s\n", addr, certDate.Format("2006-01-02 15:04:05"))
		log.Printf("Which is after %.0f days\n", days.Hours()/24)
		return int(days.Hours() / 24)
	} else {
		log.Fatal("No certificates found.")
	}
	return -1
}

var (
	crtDays = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "Certificate days",
		Help: "The number of days before expiration",
	})
)

func main() {
	log.SetFlags(0)
	log.SetOutput(new(logWriter))

	prom := flag.Bool("prometheus", false, "Export data for Prometheus")
	debug := flag.Bool("debug", false, "Debugging informations")
	port := flag.Int("port", 2112, "Port for prometheus exporter, default 2112")

	flag.Parse()

	if *debug {
		log.Println("Prometheus:", *prom)
		log.Println("Port:", *port)
	}

	if len(flag.Args()) != 1 {
		fmt.Println("Usage: checkwebcertificate domain")
		os.Exit(1)
	}

	addr := flag.Args()[0]

	if *debug {
		log.Println("Domain:", addr)
	}

	if *prom {
		go func() {
			for {
				crtDays.Set(float64(checkCerts(addr, debug)))
				time.Sleep(10 * time.Second)
			}
		}()

		http.Handle("/metrics", promhttp.Handler())
		p := fmt.Sprintf(":%d", *port)
		if *debug {
			log.Println("Listening on:", p)
		}
		err := http.ListenAndServe(p, nil)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		checkCerts(addr, debug)
	}
}
