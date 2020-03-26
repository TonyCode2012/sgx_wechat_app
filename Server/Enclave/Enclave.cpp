#include <stdarg.h>
#include <stdio.h>

#include <assert.h>
#include <map>
#include <string>
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "string.h"
#include "EUtils.h"
#include "Enclave_t.h"

using namespace std;

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

// Store user account id to user phone num mapping
map<vector<uint8_t>, string> accid_phone_map;
// Store context id to user account id mapping
map<sgx_ra_context_t, vector<uint8_t>> contextid_accid_map;

/**
 * @description: Initialize remote attestation context
 * @param b_pse -> Indicate whether create pse session
 * @param p_context -> RA session
 * @return: Initialize status
 * */
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

/**
 * @description: Close remote attestation
 * @param context -> Indicate to be closed context
 * @return: Close status
 * */
sgx_status_t SGXAPI ecall_ra_close(sgx_ra_context_t context) 
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    contextid_accid_map.erase(context);
    return ret;
}

/**
 * @description: Store user account id
 * @param context -> Corresponding context
 * @param p_Gb -> Pointer to user account id
 * @param Gb_size -> User account id size
 * */
void ecall_store_account_id(sgx_ra_context_t context, uint8_t* p_Gb, uint32_t Gb_size)
{
    vector<uint8_t> Gb_v(p_Gb, p_Gb + Gb_size);
    contextid_accid_map[context] = Gb_v;
}

/**
 * @description: Decrypt user passed data
 * @param context -> Corresponding context
 * @param p_src -> Encrypted data
 * @param src_len -> Encrypted data size
 * @param p_in_mac -> Encrypted data mac
 * @return: Decrypted status
 * */
sgx_status_t ecall_decrypt_secret(sgx_ra_context_t context,
        const uint8_t *p_src, uint32_t src_len, 
        const sgx_aes_gcm_128bit_tag_t *p_in_mac)
{   
    if (contextid_accid_map.find(context) == contextid_accid_map.end())
    {
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_ra_key_128_t ra_key;
    string phone_num;

    sgx_status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &ra_key);
    if (SGX_SUCCESS != sgx_status)
    {
        return sgx_status;
    }

    feprintf("ra key:%s\n", hexstring(&ra_key, sizeof(ra_key)));
    
    uint8_t *p_iv = (uint8_t*)malloc(SGX_AESGCM_IV_SIZE);
    memset(p_iv, 0, SGX_AESGCM_IV_SIZE);
    uint8_t *p_dst = (uint8_t*)malloc(src_len);
    memset(p_dst, 0, src_len);
    sgx_status = sgx_rijndael128GCM_decrypt(&ra_key, p_src,
            src_len, p_dst, p_iv, SGX_AESGCM_IV_SIZE, NULL, 0, p_in_mac);

    if (SGX_SUCCESS != sgx_status)
    {
        sgx_status = SGX_ERROR_UNEXPECTED;
        goto cleanup;
    }

    phone_num = string(hexstring(p_dst, src_len));
    phone_num = phone_num.substr(0, 11);
    accid_phone_map[contextid_accid_map[context]] = phone_num;

    feprintf("Phone number:%s\n", accid_phone_map[contextid_accid_map[context]]);


cleanup:

    free(p_iv);
    free(p_dst);

    return sgx_status;
}
