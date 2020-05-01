#!/bin/bash
# https://access.redhat.com/solutions/28965
# https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309
# https://gist.github.com/sethvargo/81227d2316207b7bd110df328d83fad8
# https://www.ibm.com/support/knowledgecenter/SSGSPN_8.6.0/com.ibm.tivoli.itws.doc_8.6/awsadconvertpemtocms.htm
# https://janikvonrotz.ch/2019/01/22/create-pkcs12-key-and-truststore-with-keytool-and-openssl/

ROOT_CN=rootca
SERVER_CN=mqserver
CLIENT_CN=mqclient
C=AU
ST=VIC
L=Melbourne
O=IBM
OU=HCI
DNS_1=mymqserver.blah.com
IP_1=10.0.0.10
PASS=Passw0rd!
IKEYCMD_PATH=/opt/mqm/java/jre64/jre/bin
KEYTOOL_PATH=/opt/mqm/java/jre64/jre/bin

CreateExtFile() {
cat > ${SERVER_CN}.cnf << EOF
[req]
default_bits = 4096
encrypt_key  = no # Change to encrypt the private key using des3 or similar
default_md   = sha256
prompt       = no
utf8         = yes
# Speify the DN here so we aren't prompted (along with prompt = no above).
distinguished_name = req_distinguished_name
# Extensions for SAN IP and SAN DNS
req_extensions = v3_req
# Be sure to update the subject to match your organization.
[req_distinguished_name]
C  = ${C}
ST = ${ST}
L  = ${L}
O  = ${O}
OU = ${OU}
CN = ${SERVER_CN}
# Allow client and server auth. You may want to only allow server auth.
# Link to SAN names.
[v3_req]
basicConstraints     = CA:FALSE
subjectKeyIdentifier = hash
keyUsage             = digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth
subjectAltName       = @alt_names
# Alternative names are specified as IP.# and DNS.# for IP addresses and
# DNS accordingly. 
[alt_names]
IP.1  = ${IP_1}
DNS.1 = ${DNS_1}
EOF

cat > ${CLIENT_CN}.cnf << EOF
[req]
default_bits = 4096
encrypt_key  = no # Change to encrypt the private key using des3 or similar
default_md   = sha256
prompt       = no
utf8         = yes
# Speify the DN here so we aren't prompted (along with prompt = no above).
distinguished_name = req_distinguished_name
# Extensions for SAN IP and SAN DNS
req_extensions = v3_req
# Be sure to update the subject to match your organization.
[req_distinguished_name]
C  = ${C}
ST = ${ST}
L  = ${L}
O  = ${O}
OU = ${OU}
CN = ${CLIENT_CN}
# Allow client and server auth. You may want to only allow server auth.
# Link to SAN names.
[v3_req]
basicConstraints     = CA:FALSE
subjectKeyIdentifier = hash
keyUsage             = digitalSignature, keyEncipherment
extendedKeyUsage     = clientAuth
EOF
}

CreateRootCA() {
  echo "------------------------------------------------------------------------"
  echo "Create root CA"
  openssl genrsa -out ${ROOT_CN}.key 4096
  openssl req \
      -x509 \
      -new \
      -nodes \
      -key ${ROOT_CN}.key \
      -sha256 \
      -days 3650 \
      -out ${ROOT_CN}.crt \
      -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${ROOT_CN}"
}

CreateCSR() {
  echo "------------------------------------------------------------------------"
  echo "Create server certificate request"
  openssl req \
      -new \
      -newkey rsa:4096 \
      -nodes \
      -sha256 \
      -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${SERVER_CN}" \
      -out ${SERVER_CN}.csr \
      -keyout ${SERVER_CN}.key \
      -config ${SERVER_CN}.cnf
  echo "------------------------------------------------------------------------"
  echo "Create client certificate request"
  openssl req \
      -new \
      -newkey rsa:4096 \
      -nodes \
      -sha256 \
      -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${CLIENT_CN}" \
      -out ${CLIENT_CN}.csr \
      -keyout ${CLIENT_CN}.key \
      -config ${CLIENT_CN}.cnf
}

SignCSR() {
  echo "------------------------------------------------------------------------"
  echo "Sign server certificate request with root CA"
  openssl x509 \
      -req \
      -in ${SERVER_CN}.csr \
      -CA ${ROOT_CN}.crt \
      -CAkey ${ROOT_CN}.key \
      -CAcreateserial \
      -days 3650 \
      -extensions v3_req \
      -extfile ${SERVER_CN}.cnf \
      -out ${SERVER_CN}.crt \
      -sha256
  echo "------------------------------------------------------------------------"
  echo "Sign client certificate request with root CA"
  openssl x509 \
      -req \
      -in ${CLIENT_CN}.csr \
      -CA ${ROOT_CN}.crt \
      -CAkey ${ROOT_CN}.key \
      -CAcreateserial \
      -days 3650 \
      -extensions v3_req \
      -extfile ${CLIENT_CN}.cnf \
      -out ${CLIENT_CN}.crt \
      -sha256
}

InspectCert() {
  echo "------------------------------------------------------------------------"
  echo "Inspect server certificate"
  openssl x509 -in ${SERVER_CN}.crt -text -noout
  echo "------------------------------------------------------------------------"
  echo "Inspect client certificate"
  openssl x509 -in ${CLIENT_CN}.crt -text -noout
}

ConvertPEMToPKCS12() {
  echo "------------------------------------------------------------------------"
  echo "Convert server certificate PEM to PKCS12"
  # cat ${SERVER_CN}.crt ${SERVER_CN}.key ${ROOT_CN} > ${SERVER_CN}.pem
  openssl pkcs12 \
      -export \
      -in ${SERVER_CN}.crt \
      -inkey ${SERVER_CN}.key \
      -out ${SERVER_CN}.p12 \
      -name ${SERVER_CN} \
      -passin pass:${PASS} \
      -passout pass:${PASS}
  ${KEYTOOL_PATH}/keytool -importcert -trustcacerts -file ${ROOT_CN}.crt -keystore ${SERVER_CN}.p12 -storetype PKCS12 -storepass ${PASS} -alias ${ROOT_CN} -noprompt
  echo "------------------------------------------------------------------------"
  echo "Convert client certificate PEM to PKCS12"
  # cat ${CLIENT_CN}.crt ${CLIENT_CN}.key ${ROOT_CN} > ${CLIENT_CN}.pem
  openssl pkcs12 \
      -export \
      -in ${CLIENT_CN}.crt \
      -inkey ${CLIENT_CN}.key \
      -out ${CLIENT_CN}.p12 \
      -name ${CLIENT_CN} \
      -passin pass:${PASS} \
      -passout pass:${PASS}
  ${KEYTOOL_PATH}/keytool -importcert -trustcacerts -file ${ROOT_CN}.crt -keystore ${CLIENT_CN}.p12 -storetype PKCS12 -storepass ${PASS} -alias ${ROOT_CN} -noprompt
}

ListCertPCKS12KeyStore() {
  echo "------------------------------------------------------------------------"
  echo "List certificates in PCKS12 server keystore"
  openssl pkcs12 -nokeys -info \
          -in ${SERVER_CN}.p12 \
          -passin pass:${PASS}
  echo "------------------------------------------------------------------------"
  echo "List certificates in PCKS12 client keystore"
  openssl pkcs12 -nokeys -info \
          -in ${CLIENT_CN}.p12 \
          -passin pass:${PASS}
}

# IBM MQ requires the server certificate to be converted to CMS format

CreateCMSKeyDb() {
  echo "------------------------------------------------------------------------"
  echo "Create CMS key database for server"
  ${IKEYCMD_PATH}/ikeycmd -keydb \
              -create \
              -db ${SERVER_CN}.kdb \
              -stash \
              -type cms \
              -pw ${PASS}
}

ImportPKCS12ToCMSKeyDb() {
  echo "------------------------------------------------------------------------"
  echo "Import server PKCS12 into CMS key database"
  ${IKEYCMD_PATH}/ikeycmd -cert \
              -import \
              -target ${SERVER_CN}.kdb \
              -db ${SERVER_CN}.p12 \
              -target_type cms \
              -type pkcs12 \
              -label ${SERVER_CN} \
              -target_pw ${PASS} \
              -pw ${PASS}
}

SetDefaultCert() {
  echo "------------------------------------------------------------------------"
  echo "Set default certificate in CMS key database"
  ${IKEYCMD_PATH}/ikeycmd -cert \
              -setdefault \
              -db ${SERVER_CN}.kdb \
              -stashed \
              -label ${SERVER_CN}
}

AddSignerCA() {
  echo "------------------------------------------------------------------------"
  echo "Add Root CA certificate"
  ${IKEYCMD_PATH}/ikeycmd -cert \
              -add \
              -db ${SERVER_CN}.kdb \
              -label ${ROOT_CN} \
              -trust enable \
              -file ${ROOT_CN}.crt \
              -format ascii \
              -pw ${PASS}
}

ListCertCMSKeyDb() {
  echo "------------------------------------------------------------------------"
  echo "List certificate in CMS key database"
  ${IKEYCMD_PATH}/ikeycmd -cert \
              -list \
              -db ${SERVER_CN}.kdb \
              -stashed \
              -type cms
}

GetCertDetails() {
  echo "------------------------------------------------------------------------"
  echo "Get certificate details"
  ${IKEYCMD_PATH}/ikeycmd -cert \
              -details \
              -db ${SERVER_CN}.kdb \
              -stashed \
              -type cms \
              -label ${SERVER_CN}
}

CreateRootCA
CreateExtFile
CreateCSR
SignCSR
InspectCert
ConvertPEMToPKCS12
ListCertPCKS12KeyStore
CreateCMSKeyDb
ImportPKCS12ToCMSKeyDb
SetDefaultCert
AddSignerCA
ListCertCMSKeyDb
GetCertDetails
