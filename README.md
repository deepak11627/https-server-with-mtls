# https-server-with-mTLS
Demonstration of a HTTPS server with mutual TLS developed in Golang. This is a small piece of code that can help inviduals who are looking to spin up an HTTP or HTTPS server. The server is easily configurable with few parameters and use it based on your need. One can you the server.go file for the following purposes.

- Spin HTTP server 
- Spin HTTPS server 
- Spin HTTPS server with Client verification or mutual TLS.

## Usage
Use the `generate-certs.sh` script to generate the certificates required setting up and HTTPS server. You can also use your own certificates you have them ready with you, just update the certificate paths in config.json file. You may not need to execute this script if you just need a HTTP server.

Update the config.json file for initial settings HTTP/HTTPS server based on your needs.
```
{
    "port": 8080,
    "readTimeout": 5,
    "writeTimeout": 5,
    "idleTimeout": 10,
    "tlsEnabled": true,                             // leave empty or change to false if want a HTTP server only.
    "trustStore":    "./../../Client-CA-cert.pem",  // Client root CA certificates for trust store of the server. Leave empty ,if don't want to enable Server validating client certificate. 
	"serverKey":     "./../../server-key.pem",      // Private key for the HTTPS server, leave empty if don't want HTTPS server.
    "passphrase": "private-key-password",           // Leave empty if not using encrypted private keys, or else enter the passphrase for the private key
	"serverCert":    "./../../server-cert.pem",     // Server certificate for the HTTPS server, leave empty if don't want HTTPS server.
	"serverCaCerts": "./../../CA-cert.pem",         // HTTPS server's CA certificate upto the root certificate, leave empty if don't want HTTPS server
}
```

## Running Server

```
go run cmd/server/main.go
```

## Running Client
```
go run cmd/client/main.go
```
Note: you may need to update `cmd/client/main.go` with appropriate client certificate paths, if want to use client with you own certificates.

Alternativly you can also use following curl as a client,
```
curl --cert client-cert.pem --key client-key.pem --cacert CA-cert.pem https://localhost:8080
```

## Injecting your own handler for request processing
If you have your own handler for handling all the requests. You can that and pass it to the `NewServer` constructor, the code should work fine as long as the Handler impliments the `http.Handler` interface.
An eg. usage of a handler is already committed to the repo.