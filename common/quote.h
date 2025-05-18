#include <stdio.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>


// Create a key pair and load it into to the TPM2
extern TSS2_RC createAttestationKey( 
  ESYS_CONTEXT* ctx ,
  ESYS_TR* attestationKeyHandle, 
  TPM2B_PUBLIC **outAkPublic,    // needed for quote verification
  TPM2B_PRIVATE **outAkPrivate
);

// Create a quote with the attestatoinKeyHandle
extern TSS2_RC create_quote(
    ESYS_CONTEXT *ctx,
    ESYS_TR akHandle,
    TPML_PCR_SELECTION *pcrSelection,
    TPM2B_DATA *qualifyingData,
    TPM2B_ATTEST **quote,
    TPMT_SIGNATURE **signature
);


extern TSS2_RC getSigningKey (  
    ESYS_CONTEXT* ctx ,
    ESYS_TR* attestationKeyHandle, 
    TPM2B_PUBLIC **outAkPublic
);