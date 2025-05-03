#include <stdio.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_common.h> 
#define NV_INDEX 0x01100301
#define NV_SIZE 32

int main() {
    TSS2_RC rc;
    ESYS_CONTEXT *esys_ctx;

    // Initialize ESYS context
    rc = Esys_Initialize(&esys_ctx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_Initialize failed: 0x%x\n", rc);
        return 1;
    }

    // Authorize with the owner hierarchy
    ESYS_TR auth_handle = ESYS_TR_RH_OWNER;

    // Define the NV index
    TPM2B_AUTH auth = {.size = 0};  // No auth
    TPM2B_NV_PUBLIC public_info = {
        .size = 0,
        .nvPublic = {
            .nvIndex = NV_INDEX,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | TPMA_NV_,
            .authPolicy = {.size = 0},
            .dataSize = NV_SIZE
        }
    };

    rc = Esys_NV_DefineSpace(
        esys_ctx,
        auth_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &auth,
        &public_info,
        &auth_handle);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_NV_DefineSpace failed: 0x%x\n", rc);
        Esys_Finalize(&esys_ctx);
        return 1;
    }

    ESYS_TR nv_handle;
rc = Esys_TR_FromTPMPublic(
    esys_ctx,
    NV_INDEX,
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    &nv_handle);
if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Esys_TR_FromTPMPublic failed: 0x%x\n", rc);
    Esys_Finalize(&esys_ctx);
    return 1;
}


    // Prepare the data to write
    const char *data = "Hello TPM NV";
    TPM2B_MAX_NV_BUFFER nv_data = {.size = strlen(data)};
    memcpy(nv_data.buffer, data, nv_data.size);

    rc = Esys_NV_Write(
    esys_ctx,
    auth_handle,  // Authorization is still RH_OWNER
    nv_handle,    // <-- use proper ESYS_TR handle for NV index
    ESYS_TR_PASSWORD,
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    &nv_data,
    0);           // offset

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_NV_Write failed: 0x%x\n", rc);
    } else {
        printf("Data successfully written to NV index.\n");
    }

    Esys_Finalize(&esys_ctx);
    return 0;
}
