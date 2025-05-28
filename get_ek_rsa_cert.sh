# its assumed that this script runs as root
tpm2_nvread 0x01c00002 > /tmp/ek_rsa.der
openssl x509 -inform DER -in /tmp/ek_rsa.der -out /tmp/ek_rsa.pem

