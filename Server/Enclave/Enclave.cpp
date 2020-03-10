#include <stdarg.h>
#include <stdio.h>

#include <assert.h>
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "string.h"
#include "Enclave_t.h"

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};


sgx_status_t ecall_init_ra(int b_pse, sgx_ra_context_t *p_context)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse) {
        int busy_retry_times = 2;
        do {
            ret = sgx_create_pse_session();
        } while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS)
            return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    if(b_pse) {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}

sgx_status_t SGXAPI ecall_ra_close(sgx_ra_context_t context) 
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}

sgx_status_t ecall_verify_secret(sgx_ra_context_t context,
        const uint8_t *p_src, uint32_t src_len, 
        uint8_t *p_dst, const uint8_t *p_in_mac)
{   
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_ra_key_128_t ra_key;

    sgx_status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &ra_key);
    
    uint8_t *p_iv = (uint8_t*)malloc(16);
    memset(p_iv, 0, 16);
    uint8_t *p_dst = (uint8_t*)malloc(16);
    sgx_status = sgx_rijndael128GCM_decrypt(&ra_key, p_src, src_len,
            p_dst, p_iv, 16, NULL, 0, p_in_mac);
    if (SGX_SUCCESS != sgx_status)
    {
        printf("[ERROR] SGX process message 2 failed!Error code:%lx\n", sgx_status);
    }

    return sgx_status;
}
