#!/usr/bin/sh

echo "*** CA Certificate ***"
openssl genrsa -out cert-ca-key.pem 2048
openssl req -x509 -new -nodes -extensions ca_ext -config ./gencerts.cnf -subj '/O=International Union of Example Organizations/CN=Certificate issuer guy/emailAddress=ca@mail.example' -key cert-ca-key.pem -sha256 -days 10000 -out cert-ca.pem

echo -e "\n*** Server Certificate ***"
openssl genrsa -out cert-server-key.pem
openssl req -new -extensions cert_ext -config ./gencerts.cnf -subj '/O=Foo Example Organization/CN=Foo Example Organization/emailAddress=foo@mail.example' -key cert-server-key.pem -out cert-server.csr
openssl x509 -req -extensions cert_ext -extfile ./gencerts.cnf -in cert-server.csr -CA cert-ca.pem -CAkey cert-ca-key.pem -CAcreateserial -sha256 -days 10000 -out cert-server.pem
openssl verify -CAfile cert-ca.pem cert-server.pem

echo -e "\n*** Client Certificate ***"
openssl genrsa -out cert-client-key.pem
openssl req -new -extensions cert_ext -config ./gencerts.cnf -subj '/O=Bar Example Organization/CN=Bar Example Organization/emailAddress=bar@mail.example' -key cert-client-key.pem -out cert-client.csr
openssl x509 -req -extensions cert_ext -extfile ./gencerts.cnf -in cert-client.csr -CA cert-ca.pem -CAkey cert-ca-key.pem -CAcreateserial -sha256 -days 10000 -out cert-client.pem
openssl verify -CAfile cert-ca.pem cert-client.pem

rm cert-ca.srl cert-client.csr cert-server.csr
