package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	server "github.com/deepak11627/https-server-with-mtls/http-server"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", Handler)
	sc := &server.ServerConfig{
		Port:          8080,
		ReadTimeout:   5 * time.Second,
		WriteTimeout:  5 * time.Second,
		IdleTimeout:   10 * time.Second,
		TLSEnabled:    true,
		TrustStore:    "./../../Client-CA-cert.pem",
		ServerKey:     "./../../server-key.pem",
		ServerCert:    "./../../server-cert.pem",
		ServerCaCerts: "./../../CA-cert.pem",
	}
	server, err := server.NewServer(sc, r)
	if err != nil {
		log.Fatal("failed to create server, Error:", err)
	}
	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	sig := make(chan os.Signal, 0)
	signal.Notify(sig,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	go func() { // start the https server
		err := server.Start()
		if err != nil {
			log.Error("server error ", err)
		}
	}()
	log.Info("server started and ready accept requests and signals")

	select {
	case <-sig:
		log.Info("received close signal")
		server.Shutdown(ctxShutDown)
	}

}

func Handler(w http.ResponseWriter, r *http.Request) {
	log.Info("receive on request on ", r.URL.Path)
	w.Write([]byte("you visited " + r.URL.Path))
}
