# minimal-remote-attestation

minimal remote attestation (and FIM) architecture in C/C++ by leveraging IMA on Linux

# Compilation

# Setup

# Enrolling an attester

For enrolling an attester it is required to supply an ip-address, file containing pcrs 8 and 9 and a file containing a whitelist for allowed hashes for filepaths.

1. To generate the pcrs, run this on a known good system with the same kernel version and cmdline as the one expected by each attester

```bash
sudo tpm2_pcrread sha256:8,9 -o pcrs
```

2. To generate the whitelist:

```bash
# use the software-bom binary generated in /bin to generate the whitelist on the known good system
# This would create a whitelist for allowed hashes of all files in /lib
sudo ./software-bom whitelist /lib
```

3. Enroll an attester

```bash
    # enroll the attester, while the verifier is running:
    # enter the command enroll then ip
    enroll 192.168.0.123 whitelist pcrs_whitelist
```
