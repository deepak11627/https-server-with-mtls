package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// ServerConfig represents the configuration of the crosswork Config
type ServerConfig struct {
	Port       int
	TLSEnabled bool
	// Timeouts
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	// Certs
	TrustStore    string // List of trusted Client CA certificates
	ServerKey     string // Server's Private key
	ServerCert    string // Server's Certificate
	ServerCaCerts string // Server's CA certificate chain
}

func (sc *ServerConfig) GetTrustStore() ([]byte, error) {
	trustStore, err := ioutil.ReadFile(sc.TrustStore)
	if err != nil {
		return nil, err
	}
	return trustStore, nil
}

func (sc *ServerConfig) GetServerKey() ([]byte, error) {
	serverKey, err := ioutil.ReadFile(sc.ServerKey)
	if err != nil {
		return nil, err
	}
	return serverKey, nil
}

func (sc *ServerConfig) GetServerCert() ([]byte, error) {
	serverCert, err := ioutil.ReadFile(sc.ServerCert)
	if err != nil {
		return nil, err
	}
	return serverCert, nil
}

func (sc *ServerConfig) GetServerCaCerts() ([]byte, error) {
	serverCACerts, err := ioutil.ReadFile(sc.ServerCaCerts)
	if err != nil {
		return nil, err
	}
	return serverCACerts, nil
}

// HTTPServer repreents a HTTP or HTTPS server
type HTTPServer struct {
	config *ServerConfig
	server *http.Server
}

// NewServer create a Server instance
func NewServer(c *ServerConfig, handler http.Handler) (*HTTPServer, error) {
	s := &HTTPServer{config: c}
	server := &http.Server{
		ReadTimeout:  c.ReadTimeout,  // tls handshake + request body read
		WriteTimeout: c.WriteTimeout, // request body read + response write
		IdleTimeout:  c.IdleTimeout,  // connection reset timeout
		Addr:         fmt.Sprintf(":%d", s.config.Port),
		ConnState:    connStateHook,
		Handler:      handler,
	}

	if c.TLSEnabled {
		caCertPool := x509.NewCertPool()
		ts, err := s.config.GetTrustStore()
		if err != nil {
			return nil, err
		}
		caCertPool.AppendCertsFromPEM(ts)

		sKey, err := s.config.GetServerKey()
		if err != nil {
			return nil, err
		}

		sCert, err := s.config.GetServerCert()
		if err != nil {
			return nil, err
		}

		sCACert, err := s.config.GetServerCaCerts()
		if err != nil {
			return nil, err
		}

		var certs []byte
		certs = append(certs, []byte(sCert)...)

		certPEMBlock := []byte(sCACert)
		var certDERBlock *pem.Block
		count := 1
		for {
			// Extract all intermedidate certificates
			certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
			if certDERBlock == nil {
				break
			}
			if count == 1 {
				log.Info("skipping the root certificate from server certificate configration.")
				count++
				continue
			}

			if certDERBlock.Type == "CERTIFICATE" {
				log.Info("adding intermediate certificate")
				cert := &bytes.Buffer{}
				pem.Encode(cert, &pem.Block{Type: "CERTIFICATE", Bytes: certDERBlock.Bytes})
				certs = append(certs, cert.Bytes()...)
			}
		}
		fmt.Println(string(certs))
		fmt.Println(string(sKey))
		log.Info("loading server keypair")
		cert, err := tls.X509KeyPair(certs, sKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server keypair. Error: %s", err)
		}

		tlsConfig := &tls.Config{
			ClientCAs:    caCertPool,
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			//CipherSuites: ,
			MinVersion: tls.VersionTLS12,
		}
		tlsConfig.BuildNameToCertificate()
		server.TLSConfig = tlsConfig
	}
	return &HTTPServer{config: c, server: server}, nil
}

func connStateHook(c net.Conn, state http.ConnState) {
	log.Info("http connState ", state)
	if cc, ok := c.(*tls.Conn); ok {
		log.Info("Remote addr ", cc.RemoteAddr().String(), " local addr ", cc.LocalAddr().String())
	}
}

// Shutdown closes the https server gracefully
func (s *HTTPServer) Shutdown(ctx context.Context) error {
	log.Info("shutdown server")
	return s.server.Shutdown(ctx)
}

// Start starts the https server and listens for new incoming requests
func (s *HTTPServer) Start() error {
	log.Info("started server on Port: ", s.server.Addr)
	if s.config.TLSEnabled {
		err := s.server.ListenAndServeTLS("", "")
		if err != nil {
			return err
		}
	} else {
		err := s.server.ListenAndServe()
		if err != nil {
			return err
		}
	}
	return nil
}

// func decryptKeyPEM(key, passphrase string) ([]byte, error) {
// 	block, rest := pem.Decode([]byte(key))
// 	if len(rest) > 0 {
// 		return nil, errors.New("Extra data included in key")
// 	}

// 	log.Info("Block type ", block.Type)
// 	if passphrase != "" {
// 		switch block.Type {
// 		case "RSA PRIVATE KEY": // pkcs1
// 			der, err := x509.DecryptPEMBlock(block, []byte(strings.TrimSpace(passphrase)))
// 			if err != nil {
// 				return nil, fmt.Errorf("decrypt failed: %s", err)
// 			}
// 			return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der}), nil
// 		case "ENCRYPTED PRIVATE KEY": // pkcs8
// 			tempFile, err := ioutil.TempFile("", "key-tmp")
// 			if err != nil {
// 				return nil, fmt.Errorf("failed to create tmp file for key %s", err)
// 			}

// 			defer os.Remove(tempFile.Name()) // clean up

// 			if _, err := tempFile.Write([]byte(key)); err != nil {
// 				return nil, fmt.Errorf("failed to write to tmp file for key %s", err)
// 			}

// 			pkcs8KeyTmpFile, err := ioutil.TempFile("./", "pkcs8-tmp")
// 			if err != nil {
// 				return nil, fmt.Errorf("failed to create tmp file for pkcs8 %s", err)
// 			}

// 			defer os.Remove(pkcs8KeyTmpFile.Name())

// 			opensslCMD := exec.Command("openssl", "pkcs8", "-inform", "PEM", "-in", tempFile.Name(), "-passin", "pass:"+passphrase, "-out", pkcs8KeyTmpFile.Name())

// 			out, err := opensslCMD.CombinedOutput()
// 			if err != nil {
// 				return nil, fmt.Errorf("failed to decrypt pkcs8 encrypted key, error: %s, output: %s", err, fmt.Sprintf("%+v", string(out)))
// 			}

// 			decryptedPkcs8Key, err := ioutil.ReadAll(pkcs8KeyTmpFile)
// 			if err != nil {
// 				return nil, fmt.Errorf("failed to read pkcs8 file content %s", err)
// 			}
// 			return decryptedPkcs8Key, nil
// 		}
// 	}
// 	return []byte(key), nil
// }
