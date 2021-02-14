package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptrace"

	log "github.com/sirupsen/logrus"
)

func main() {
	log.Info("preparing request")
	req, _ := http.NewRequest("GET", "https://localhost:8080", nil)
	trace := &httptrace.ClientTrace{
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			fmt.Printf("DNS Info: %+v\n", dnsInfo)
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			fmt.Printf("Got Conn: %+v\n", connInfo)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	log.Info("reading client keypair")
	cert, err := tls.LoadX509KeyPair("./../../client-cert.pem", "./../../client-key.pem")
	if err != nil {
		log.Fatalf("client: loadkeys: %s", err)
	}
	caCertPool := x509.NewCertPool()
	trustStore, err := ioutil.ReadFile("./../../CA-cert.pem")
	if err != nil {
		log.Fatalf("failed to get client trust store %s", err)
	}
	caCertPool.AppendCertsFromPEM(trustStore)

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: false,
		RootCAs:            caCertPool,
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	res, err := client.Do(req)
	if err != nil {
		log.Error(err)
	}
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Error("failed to read response body")
			return
		}
		log.Info("request executed successfully, response is ", string(body))
		return
	}
	log.Error("request failed", "status", res.StatusCode)
}
