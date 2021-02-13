package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptrace"

	log "github.com/sirupsen/logrus"
)

func main() {
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
	if _, err := http.DefaultTransport.RoundTrip(req); err != nil {
		log.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair("./../../client-cert.pem", "./../../client-key.pem")
	if err != nil {
		log.Fatalf("client: loadkeys: %s", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
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
