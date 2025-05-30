# its assumed that this script runs as root
sudo tpm2_nvread 0x01c00002 > /tmp/ek_rsa.der
sudo openssl x509 -inform DER -in /tmp/ek_rsa.der -out /tmp/ek_rsa.pem
# You can print the ek_rsa.pem info to find out the vendor and where to get the root cert
