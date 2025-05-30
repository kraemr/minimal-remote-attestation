#include "quote.h"
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

#define AK_PERSISTENT_HANDLE 0x81000003



// loadAttestation Key fails, then we know that the attestation Key doesnt exist
TSS2_RC getAttestationKeyHandle(ESYS_CONTEXT* ctx,ESYS_TR* attestationKeyHandle ) {
    TSS2_RC rc;
    rc = Esys_TR_FromTPMPublic(
        ctx,
        AK_PERSISTENT_HANDLE, 
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        attestationKeyHandle
    );
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to access persistent handle: 0x%x\n", rc);
        return rc;
    }
    return TSS2_RC_SUCCESS; 
}



TSS2_RC createAttestationKey( 
  ESYS_CONTEXT* ctx ,
  ESYS_TR* attestationKeyHandle, 
  TPM2B_PUBLIC **outAkPublic,   
  TPM2B_PRIVATE **outAkPrivate)
{ 
    TSS2_RC rc = 0;
    
    //  Start: Create Primary Key (EK or SRK)
    ESYS_TR primaryHandle;
    TPM2B_AUTH authValue = {.size = 0};
    TPM2B_SENSITIVE_CREATE inSensitive = {
      .size = 0,
      .sensitive =
          {
              .userAuth = authValue,
              .data =
                  {
                      .size = 0,
                  },
          },
    };

    TPM2B_PUBLIC inPublic = {
      .size = 0,
      .publicArea =
          {
              .type = TPM2_ALG_RSA,
              .nameAlg = TPM2_ALG_SHA256,
              .objectAttributes =
                  TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT |
                  TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                  TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
              .authPolicy =
                  {
                      .size = 0,
                  },
                
              .parameters.rsaDetail =
                  {
                      .symmetric =
                          {
                              .algorithm = TPM2_ALG_AES,
                              .keyBits.aes = 128,
                              .mode.aes = TPM2_ALG_CFB,
                          },
                      .scheme =
                          {
                              .scheme = TPM2_ALG_NULL,
                          },
                      .keyBits = 2048,
                      .exponent = 0,
                  },
              .unique.rsa.size = 0,
          },
    };
    TPM2B_DATA outsideInfo = {.size = 0};
    TPML_PCR_SELECTION creationPCR = {.count = 0};
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    TPM2B_NAME *name = NULL;

    rc = Esys_CreatePrimary(
      ctx, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
      &inSensitive, &inPublic, &outsideInfo, &creationPCR, &primaryHandle,
      &outPublic, &creationData, &creationHash, &creationTicket);

    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_CreatePrimary failed: 0x%x\n", rc);
        return 1;
    }

    // Now: Create Attestation Key under Primary
    TPM2B_PUBLIC akTemplate = {
      .size = 0,
      .publicArea = {
          .type = TPM2_ALG_RSA,
          .nameAlg = TPM2_ALG_SHA256,
          .objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM |
                              TPMA_OBJECT_FIXEDPARENT |
                              TPMA_OBJECT_SENSITIVEDATAORIGIN |
                              TPMA_OBJECT_USERWITHAUTH,
          .authPolicy = {.size = 0},
          .parameters.rsaDetail =
              {
                  .symmetric = {.algorithm = TPM2_ALG_NULL},
                  .scheme =
                      {
                          .scheme = TPM2_ALG_RSASSA,
                          .details.rsassa.hashAlg = TPM2_ALG_SHA256,
                      },
                  .keyBits = 2048,
                  .exponent = 0,
              },
          .unique.rsa = {.size = 0},
          }};

    TPM2B_SENSITIVE_CREATE akSensitive = {.size = 0,
                                        .sensitive = {
                                            .userAuth = {.size = 0},
                                            .data = {.size = 0},
                                        }};

    TPM2B_PUBLIC *akOutPublic;
    TPM2B_PRIVATE *akPrivate;
    TPM2B_CREATION_DATA *akCreationData;
    TPM2B_DIGEST *akCreationHash;
    TPMT_TK_CREATION *akCreationTicket;

    rc = Esys_Create(ctx, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                       ESYS_TR_NONE, &akSensitive, &akTemplate, &outsideInfo,
                    &creationPCR, outAkPrivate, outAkPublic, &akCreationData,
                   &akCreationHash, &akCreationTicket);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Create (AK) failed: 0x%x\n", rc);
        return 1;
    }

    // Load the AK into TPM
    //ESYS_TR akHandle;
    rc = Esys_Load(ctx, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                 ESYS_TR_NONE, *outAkPrivate,*outAkPublic, attestationKeyHandle);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Load (AK) failed: 0x%x\n", rc);
        return 1;
    }
    ESYS_TR authHandle = ESYS_TR_RH_OWNER; // Usually TPM_RH_OWNER
    ESYS_TR out = 0;
    // Authorize with the TPM owner hierarchy
    rc = Esys_EvictControl(
    ctx,
    authHandle,         // TPM_RH_OWNER
    *attestationKeyHandle,           // The loaded transient AK handle
    ESYS_TR_PASSWORD,   // Auth session (password)
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    AK_PERSISTENT_HANDLE,
    &out);
    
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "EvictControl failed: 0x%x\n", rc);
        return rc;
    }
    
    (*attestationKeyHandle) = out;
    printf("Attestation Key created and loaded successfully.\n");
    return TSS2_RC_SUCCESS;
}

TSS2_RC loadAttestationKey(  
    ESYS_CONTEXT* ctx ,
    ESYS_TR attestationKeyHandle, 
    TPM2B_PUBLIC **outAkPublic
) 
{


    TPM2B_NAME* name = NULL;
    TPM2B_NAME* qualifiedName = NULL;

    TSS2_RC rc = Esys_ReadPublic(
        ctx,
        attestationKeyHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        outAkPublic,      // <-- Output: public part here
        &name,
        &qualifiedName
    );
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_ReadPublic failed: 0x%x\n", rc);
    }

    Esys_Free(name);
    Esys_Free(qualifiedName);

    
    return TSS2_RC_SUCCESS;
}

TSS2_RC create_quote(
    ESYS_CONTEXT *ctx,
    ESYS_TR akHandle,
    TPML_PCR_SELECTION *pcrSelection,
    TPM2B_DATA *qualifyingData,
    TPM2B_ATTEST **quote,
    TPMT_SIGNATURE **signature
){
 
  TSS2_RC rc;
  TPMU_SIG_SCHEME sc;
  TPMT_SIG_SCHEME scheme = {TPM2_ALG_NULL,sc};

    rc = Esys_Quote(ctx,
                    akHandle,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    qualifyingData,
                    &scheme,  // Use default scheme defined in AK
                    pcrSelection,
                    quote,
                    signature);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_Quote failed: 0x%x\n", rc);
        return rc;
    }

    return TSS2_RC_SUCCESS;

  return 0;
}

TSS2_RC getSigningKey (   
    ESYS_CONTEXT* ctx ,
    ESYS_TR* attestationKeyHandle, 
    TPM2B_PUBLIC **outAkPublic) 
{
    TSS2_RC rc = getAttestationKeyHandle(ctx,attestationKeyHandle);    
    if(rc != TSS2_RC_SUCCESS) return rc;  
    rc = loadAttestationKey(ctx,*attestationKeyHandle,outAkPublic);
    if(rc != TSS2_RC_SUCCESS) return rc;
    return rc;
}
