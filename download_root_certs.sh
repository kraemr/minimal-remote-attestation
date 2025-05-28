#!/bin/bash

root_cert_urls=(
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201111.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202111.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202112.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/NuvotonTPMRootCA1210.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201014.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202011.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202012.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201110.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202110.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/NTC_TPM_EK_Root_CA_ARSUF_01.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201013.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%202010.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/NTC%20TPM%20EK%20Root%20CA%2001.cer"
  "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/NTC%20TPM%20EK%20Root%20CA%2002.cer"
  
)

# Exit on error
set -e
CERT_DIR="root-certs"
BUNDLE_FILE="root_bundle.pem"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR" || exit 1


# Download, convert to PEM, and append to bundle
> "$BUNDLE_FILE"  # Clear any existing bundle

for url in "${root_cert_urls[@]}"; do
  filename=$(basename "$url" | sed 's/%20/ /g')
  pemfile="${filename%.cer}.pem"

  echo "Downloading: $filename"
  curl -s -L "$url" -o "$filename"

  echo "Converting to PEM: $pemfile"
  openssl x509 -inform DER -in "$filename" -out "$pemfile"

  echo "Adding $pemfile to bundle"
  cat "$pemfile" >> "$BUNDLE_FILE"
  echo "" >> "$BUNDLE_FILE"  # Add newline between certs
done

echo "All certificates downloaded, converted, and bundled in: $CERT_DIR/$BUNDLE_FILE"
