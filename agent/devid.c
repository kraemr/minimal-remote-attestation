#include <string.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <stdio.h>

#define NV_INDEX 0x1100301
#define NV_SIZE 32

TSS2_RC readDevId(ESYS_CONTEXT* esys_ctx,uint8_t buf[32]) {
    TSS2_RC rc;
 // 2. Convert NV index to ESYS_TR
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
      
        return 1;
    }

    // 3. Read from NV
    TPM2B_MAX_NV_BUFFER *nv_data = NULL;
    rc = Esys_NV_Read(
        esys_ctx,
        ESYS_TR_RH_OWNER,  
        nv_handle,         
        ESYS_TR_PASSWORD,  
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        NV_SIZE,           
        0,                
        &nv_data);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_NV_Read failed: 0x%x\n", rc);
      
        return 1;
    }

    // 4. Print result
    printf("Read %u bytes from NV index:\n", nv_data->size);
    for (size_t i = 0; i < nv_data->size; i++) {
        printf("%02x ", nv_data->buffer[i]);
    }
    printf("\n");

    return 0;
}


TSS2_RC writeDevId(ESYS_CONTEXT* esys_ctx,const uint8_t* data, uint32_t size) {
    TSS2_RC rc;
    ESYS_TR auth_handle = ESYS_TR_RH_OWNER;
    // Define the NV index
    TPM2B_AUTH auth = {.size = 0};  // No auth
    TPM2B_NV_PUBLIC public_info = {
        .size = 0,
        .nvPublic = {
            .nvIndex = NV_INDEX,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD,
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
       
        return 1;
    }

    TPM2B_MAX_NV_BUFFER nv_data = {.size = size };
    memcpy(nv_data.buffer, data, nv_data.size);

    rc = Esys_NV_Write(
    esys_ctx,
    auth_handle,
    nv_handle,    
    ESYS_TR_PASSWORD,
    ESYS_TR_NONE,
    ESYS_TR_NONE,
    &nv_data,
    0);           

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_NV_Write failed: 0x%x\n", rc);
    } else {
        printf("Data successfully written to NV index.\n");
    }

    Esys_Finalize(&esys_ctx);
    return 0;

}