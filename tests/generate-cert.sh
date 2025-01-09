#!/bin/bash

# Create CA private key (provide a password for the key):
openssl ecparam -name prime256v1 -genkey -noout -out ca_ec.key

# Create CA certificate (provide suitable input when asked):
openssl req -x509 -new -nodes -key ca_ec.key -sha256 -days 1024 -set_serial 1 -out ca_ec.pem -subj "/O=SomeOrg/OU=Test/CN=Test RootCA" -config ./test_openssl.cnf

# Print the CA
openssl x509 -in ca_ec.pem -text -noout

# ## Intermediate EC cert ##
# # Generate test private keys
# openssl ecparam -name prime256v1 -genkey -noout -out intermediate_signing.key

# # Create CSR requirements file:
# openssl req -new -key intermediate_signing.key -out intermediate_signing.csr -subj "/O=SomeOrg/OU=Test/CN=Test camera"

# # Sign CSR
# openssl x509 -req -in intermediate_signing.csr -CA ca_ec.pem -CAkey ca_ec.key -CAcreateserial -out intermediate_signing.crt -days 365 -sha256 -extensions req_ext

# # Print signed certificate
# openssl x509 -in intermediate_signing.crt -text -noout

# # Verify certificate
# openssl verify -verbose -CAfile ca_ec.pem intermediate_signing.crt

## EC ##
# Create CSR requirements file:
# openssl req -new -key ec_signing.key -out ec_signing.csr -subj "/O=SomeOrg/OU=Test/CN=Test camera"
openssl req -new -key private_ecdsa_key.pem -out ec_signing.csr -subj "/O=SomeOrg/OU=Test/CN=Test camera"

# Sign CSR
openssl x509 -req -in ec_signing.csr -CA ca_ec.pem -CAkey ca_ec.key -CAcreateserial -out ec_signing.crt -days 365 -sha256 -extensions req_ext
# openssl x509 -req -in ec_signing.csr -CA intermediate_signing.crt -CAkey intermediate_signing.key -CAcreateserial -out ec_signing.crt -days 365 -sha256 -extensions req_ext

# Print signed certificate
openssl x509 -in ec_signing.crt -text -noout

# Verify certificate
openssl verify -verbose -CAfile ca_ec.pem ec_signing.crt
# openssl verify -verbose -CAfile intermediate_signing.crt ec_signing.crt

# Concatenate certificates
cat ec_signing.crt ca_ec.pem > cert_chain.pem
# cat ec_signing.crt intermediate_signing.crt ca_ec.pem > cert_chain.pem
