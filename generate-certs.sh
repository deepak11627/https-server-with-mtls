#  ---------  Server --------------
# CA Certificate
openssl genrsa -out CA-key.pem 2048
openssl req -x509 -new -nodes -key CA-key.pem -sha256 -days 1024 -subj '/CN=Root CA' -out CA-cert.pem

# Server Certificate
openssl genrsa -out server-key.pem 2048
openssl req -new  -key server-key.pem -out server.csr -subj "/C=IN/ST=UP/L=Ghaziabad/O=Server-Certificate/CN=localhost"
openssl x509 -req -sha256 -days 1024 -in server.csr -CA CA-cert.pem -CAkey CA-key.pem -CAcreateserial -extfile domain.ext -out server-cert.pem

#  ---------  Client --------------
# Client CA Certificate
openssl genrsa -out Client-CA-key.pem 2048
openssl req -x509 -new -nodes -key Client-CA-key.pem -sha256 -days 1024 -subj '/CN=Root CA' -out Client-CA-cert.pem

# Client Certificate
openssl genrsa -out client-key.pem 2048
openssl req -new -sha256 -key client-key.pem -subj "/C=IN/ST=UP/O=Self, Inc./CN=localhost" -out client.csr
openssl x509 -req -in client.csr -CA Client-CA-cert.pem -CAkey Client-CA-key.pem -CAcreateserial -out client-cert.pem -days 500 -sha256 


