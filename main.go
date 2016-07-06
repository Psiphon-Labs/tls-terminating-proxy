package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
)

type stringListFlag []string

func (list *stringListFlag) String() string {
	return strings.Join(*list, ", ")
}

func (list *stringListFlag) Set(flagValue string) error {
	*list = append(*list, flagValue)
	return nil
}

var localAddress, backendAddress string
var caPath, certificatePath, keyPath string
var logPath string
var allowableCns stringListFlag

func main() {
	flag.StringVar(&logPath, "log", "", "local address")
	flag.StringVar(&caPath, "ca", "ssl/ca.pem", "SSL CA certificate path")
	flag.StringVar(&certificatePath, "server-certificate", "ssl/cert.pem", "SSL server certificate path")
	flag.StringVar(&keyPath, "server-key", "ssl/key.pem", "SSL server key path")
	flag.StringVar(&localAddress, "local", ":44300", "local address")
	flag.StringVar(&backendAddress, "backend", "localhost:9999", "backend address")
	flag.Var(&allowableCns, "cn", "whitelist of allowed CNs in the client certificate (this flag can be repeated to allow multiple CNs)")
	flag.Parse()

	if logPath != "" {
		logFile, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}
		defer logFile.Close()

		log.SetOutput(logFile)
	}

	cert, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		log.Fatalf("Error in tls.LoadX509KeyPair: %s\n", err)
	}

	caPool := x509.NewCertPool()
	serverCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.Fatalf("Could not load CA certificate from '%s'\n", caPath)
	}
	caPool.AppendCertsFromPEM(serverCert)

	tlsConfig := tls.Config{
		RootCAs:            caPool,
		ClientCAs:          caPool,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: false,
	}

	listener, err := tls.Listen("tcp", localAddress, &tlsConfig)
	if err != nil {
		log.Fatalf("Could not start TLS listener: %s\n", err)
	}

	log.Printf("Proxy now terminating SSL on: %s, forwarding to: %s\n", localAddress, backendAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Unable to accept new connection: %s\n", err)
			break
		}

		go handleConnection(conn)
	}
}

func handleConnection(client net.Conn) {
	tlsConnection, ok := client.(*tls.Conn)
	if ok {
		err := tlsConnection.Handshake()
		if err != nil {
			log.Printf("Error during handshake: %s\n", err)
			client.Close()
			return
		}

		clientCn := tlsConnection.ConnectionState().PeerCertificates[0].Subject.CommonName
		if len(allowableCns) == 0 {
			log.Println("No allowable CNs passed, allowing any")
		} else {
			for _, cnCandidate := range allowableCns {
				if clientCn == cnCandidate {
					break
				} else {
					log.Printf("Client certificate for: %s was not in the whitelist, not relaying\n", clientCn)
					client.Close()
					return
				}
			}
		}

		backend, err := net.Dial("tcp", backendAddress)
		if err != nil {
			log.Printf("Error connecting to back end: %s\n", err)
			client.Close()
			return
		}

		go relayTraffic(client, backend)
		go relayTraffic(backend, client)
	}
}

func relayTraffic(from, to io.ReadWriteCloser) {
	// This deferred recover allows a panicking go routine to die without affecting the others
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic while tunneling: %s\n", r)
		}
	}()

	io.Copy(from, to)
	to.Close()
	from.Close()
}
