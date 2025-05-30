# minimal-remote-attestation

minimal remote attestation (and FIM) architecture in C/C++ by leveraging IMA on Linux

# Prerequisites
Packages needed:
libcbor
libtss2
libtss2-mu
libopenssl
libcurl
tpm2-tools
curl


# Setup

```bash
# This downloads root certs for nuvoton, If this fails you can always just try to find your certificate/s manually
./download_root_certs.sh



```


# Enrolling an attester
