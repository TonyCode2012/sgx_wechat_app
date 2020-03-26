#include "MessageHandler.h"
#include "Json.hpp"
#include "Common.h"
#include "SgxSupport.h"

using namespace std;

extern FILE *felog;


MessageHandler::MessageHandler()
{
    if (SGX_SUCCESS != init_enclave())
    {
        exit(-1);
    }
}

/**
 * @description: Initialize enclave
 * @return: Initialize status
 * */
sgx_status_t MessageHandler::init_enclave()
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    int launch_token_update = 0;
    int enclave_lost_sgx_statusry_time = 3;
    sgx_launch_token_t launch_token = {0};

    memset(&launch_token, 0, sizeof(sgx_launch_token_t));

    do {
        sgx_status = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG,
                &launch_token, &launch_token_update, &this->enclave_id, NULL);
        printf_info(felog, "enclave_id:%" PRIu64 "\n",this->enclave_id);

        if (enclave_lost_sgx_statusry_time <= 0) 
        {
            printf_err(felog, "Call sgx_create_enclave fail! ErrorCode:%lx\n", sgx_status);
            goto cleanup;
        } 
        printf_info(felog, "Call sgx_create_enclave successfully!\n");

    } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_sgx_statusry_time--);

    printf_info(felog, "Enclave created, ID: %llx\n", this->enclave_id);

cleanup:

    return sgx_status;
}

/**
 * @description: Remote attestation handle Message0
 * @return: Message2
 * */
string MessageHandler::handle_att_msg0()
{

    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_status_t ra_status = SGX_SUCCESS;
    sgx_ra_msg1_t ra_msg1;
    int retry = 5;
    json::JSON msg1_json;

    if (SGX_SUCCESS != (sgx_status = ecall_init_ra(this->enclave_id, &ra_status, 
                    false, &this->ra_context))
            || SGX_SUCCESS != ra_status )
    {
        if (SGX_SUCCESS != sgx_status)
        {
            printf_err(felog, "Invoke SGX failed!Error code:%lx\n", sgx_status);
        }
        else
        {
            printf_err(felog, "Init remote attestation failed!Error code:%lx\n", ra_status);
        }
        msg1_json["status"] = "failed";
        goto cleanup;
    }

    do {
        sgx_status = sgx_ra_get_msg1(this->ra_context, this->enclave_id,
                sgx_ra_get_ga, &ra_msg1);

        if(SGX_SUCCESS == sgx_status)
            break;
        
        if (SGX_ERROR_BUSY == sgx_status) 
        {
            if (retry <= 0) 
            { 
                //retried 5 times, so fail out
                printf_err(felog, "sgx_ra_get_msg1 is busy - 5 retries failed!\n");
                break;
            }
            sleep(3);
            retry--;
        } 
        else 
        {    
            //error other than busy
            printf_err(felog, "Failed to generate MSG1,error code:%lx\n", sgx_status);
            break;
        }

    } while(true);

    if (SGX_SUCCESS != sgx_status)
    {
        ecall_ra_close(this->enclave_id, &sgx_status, this->ra_context);
        msg1_json["status"] = "failed";
    }
    else
    {
        /* Assemble msg1 */
        printf("gax:     = %s\n", hexstring(ra_msg1.g_a.gx,sizeof(ra_msg1.g_a.gx)));
        printf("gay:     = %s\n", hexstring(ra_msg1.g_a.gy,sizeof(ra_msg1.g_a.gy)));
        msg1_json["gax"] = hexstring(switch_endian(ra_msg1.g_a.gx,sizeof(ra_msg1.g_a.gx)), sizeof(ra_msg1.g_a.gx));
        msg1_json["gay"] = hexstring(switch_endian(ra_msg1.g_a.gy,sizeof(ra_msg1.g_a.gy)), sizeof(ra_msg1.g_a.gy));
        msg1_json["gid"] = hexstring(switch_endian(ra_msg1.gid,sizeof(ra_msg1.gid)), sizeof(ra_msg1.gid));
        msg1_json["status"] = "successfully";
    }

cleanup:

    return msg1_json.dump();
}

/**
 * @description: Remote attestation handle Message2
 * @param msg2_str -> Message2 content
 * @return: Message3
 * */
string MessageHandler::handle_att_msg2(string msg2_str)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_ra_msg2_t *p_msg2 = (sgx_ra_msg2_t*)malloc(sizeof(sgx_ra_msg2_t));
    json::JSON msg3_json;
    memset(p_msg2, 0, sizeof(sgx_ra_msg2_t));

    /* Assemble msg2 */
    json::JSON msg2_json = json::JSON::Load(msg2_str);
    string gbx = msg2_json["gbx"].ToString();
    string gby = msg2_json["gby"].ToString();
    string spid = msg2_json["spid"].ToString();
    string quote_type = msg2_json["quoteType"].ToString();
    string kdf_id = msg2_json["kdfId"].ToString();
    string sigSP_x = msg2_json["SigSPX"].ToString();
    string sigSP_y = msg2_json["SigSPY"].ToString();
    string cmac_smk = msg2_json["CMACsmk"].ToString();
    from_hexstring((uint8_t*)p_msg2->g_b.gx, gbx.c_str(), SGX_ECP256_KEY_SIZE);
    from_hexstring((uint8_t*)p_msg2->g_b.gy, gby.c_str(), SGX_ECP256_KEY_SIZE);
    from_hexstring((uint8_t*)&p_msg2->spid, spid.c_str(), 16);
    from_hexstring((uint8_t*)&p_msg2->quote_type, quote_type.c_str(), 2);
    from_hexstring((uint8_t*)&p_msg2->kdf_id, kdf_id.c_str(), 2);
    from_hexstring((uint8_t*)p_msg2->sign_gb_ga.x, sigSP_x.c_str(), 32);
    from_hexstring((uint8_t*)p_msg2->sign_gb_ga.y, sigSP_y.c_str(), 32);
    from_hexstring((uint8_t*)&p_msg2->mac, cmac_smk.c_str(), SGX_MAC_SIZE);
    p_msg2->sig_rl_size = 0;

    /* Print message2 */
    printf("\n===== Msg2 Details =====\n");
    printf("msg2.g_b.gx      = %s\n", hexstring(p_msg2->g_b.gx, SGX_ECP256_KEY_SIZE));
    printf("msg2.g_b.gy      = %s\n", hexstring(p_msg2->g_b.gy, SGX_ECP256_KEY_SIZE));
    printf("msg2.spid        = %s\n", hexstring(&p_msg2->spid, 16));
    printf("msg2.quote_type  = %s\n", hexstring(&p_msg2->quote_type, 2));
    printf("msg2.kdf_id      = %s\n", hexstring(&p_msg2->kdf_id, 2));
    printf("msg2.sign_ga_gb  = %s\n", hexstring(&p_msg2->sign_gb_ga, 64));
    printf("msg2.mac         = %s\n", hexstring(&p_msg2->mac, SGX_MAC_SIZE));


    /* Get msg3 */
    sgx_ra_msg3_t *p_msg3 = NULL;
    uint32_t msg3_size;
    int retry = 3;

    do {
        sgx_status = sgx_ra_proc_msg2(this->ra_context, this->enclave_id, 
                sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
                p_msg2, sizeof(sgx_ra_msg2_t), &p_msg3, &msg3_size);

        if (SGX_SUCCESS == sgx_status)
            break;

        if (SGX_ERROR_BUSY == sgx_status)
        {
            if (retry <= 0)
            {
                printf("[ERROR] Having retried %d times!\n", retry);
                break;
            }
            printf("[WARN] SGX busy try it again...\n");
            sleep(1);
            retry--;
        }
        else
        {
            printf("[ERROR] SGX process message 2 failed!Error code:%d\n", sgx_status);
            break;
        }

    } while (true);

    if(SGX_SUCCESS != sgx_status)
    {
        printf("[ERROR] sgx process msg2 failed:%d\n",sgx_status);
        ecall_ra_close(this->enclave_id, &sgx_status, this->ra_context);
        msg3_json["status"] = "failed";
    }
    else
    {
        printf("[INFO] sgx process msg2 successfully!\n");
        uint32_t quote_size = 0;
        //if (SGX_SUCCESS != sgx_get_quote_size(NULL, &quote_size))
        if (!get_quote_size(&sgx_status, &quote_size)
                || SGX_SUCCESS != sgx_status)
        {
            printf("[ERROR] Get quote size failed!Error code:%d\n", sgx_status);
            msg3_json["status"] = "failed";
        }
        else
        {
            msg3_json["status"] = "successfully";
            msg3_json["mac"] = string(hexstring(p_msg3->mac, SGX_MAC_SIZE));
            msg3_json["gax"] = string(hexstring(p_msg3->g_a.gx, SGX_ECP256_KEY_SIZE));
            msg3_json["gay"] = string(hexstring(p_msg3->g_a.gy, SGX_ECP256_KEY_SIZE));
            msg3_json["ps_sec_prop"] = string(hexstring(&p_msg3->ps_sec_prop, 256));
            msg3_json["quote"] = string(hexstring(&p_msg3->quote, quote_size));

            printf("\n======== Msg3 Details ========\n");
            printf("status          = %s\n", msg3_json["status"].ToString().c_str());
            printf("mac             = %s\n", msg3_json["mac"].ToString().c_str());
            printf("gax             = %s\n", msg3_json["gax"].ToString().c_str());
            printf("gay             = %s\n", msg3_json["gay"].ToString().c_str());
            printf("ps_sec_prop     = %s\n", msg3_json["ps_sec_prop"].ToString().c_str());
            printf("quote           = %s\n\n", msg3_json["quote"].ToString().c_str());

            // Store Gb
            string Gb = gbx.append(gby);
            uint8_t *p_Gb = (uint8_t*)malloc(SGX_ECP256_KEY_SIZE*2);
            memset(p_Gb, 0, SGX_ECP256_KEY_SIZE*2);
            from_hexstring(p_Gb, Gb.c_str(), SGX_ECP256_KEY_SIZE*2);
            if (SGX_SUCCESS != ecall_store_account_id(this->enclave_id, this->ra_context, p_Gb, SGX_ECP256_KEY_SIZE*2))
            {
                printf_err(felog, "Store account id failed!Error:invoke SGX failed!\n");
                ecall_ra_close(this->enclave_id, &sgx_status, this->ra_context);
                msg3_json["status"] = "failed";
            }
            else
            {
                printf_info(felog, "Store user account id successfully!\n");
            }
        }
    }

    return msg3_json.dump();
}

/**
 * @description: Remote attestation handle Message4
 * @param msg4_str -> Message4 content
 * @return: Handle result
 * */
string MessageHandler::handle_att_msg4(string msg4_str)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    json::JSON msg4_json = json::JSON::Load(msg4_str);


    printf("\n======== Msg4 Details ========\n");
    printf("%s\n", msg4_json.dump().c_str());

    std::string cipherText = msg4_json["cipherText"].ToString();
    std::string auth_tag = msg4_json["auth_tag"].ToString();
    // Get encrypted data
    size_t src_len = cipherText.size() / 2;
    uint8_t *p_src = (uint8_t*)malloc(src_len);
    memset(p_src, 0, src_len);
    from_hexstring(p_src, cipherText.c_str(), src_len);
    // Get auth mac
    sgx_aes_gcm_128bit_tag_t *p_in_mac = (sgx_aes_gcm_128bit_tag_t*)malloc(sizeof(sgx_aes_gcm_128bit_tag_t));
    memset(p_in_mac, 0, sizeof(sgx_aes_gcm_128bit_tag_t));
    from_hexstring((uint8_t*)p_in_mac, auth_tag.c_str(), sizeof(sgx_aes_gcm_128bit_tag_t));
    // Allocate decrypted buffer

    /* Verify secret */
    ecall_decrypt_secret(this->enclave_id, &sgx_status, this->ra_context, 
            p_src, src_len, p_in_mac);
    if (SGX_SUCCESS != sgx_status)
    {
        printf_err(felog, "Verify secret failed!Error code:%lx\n", sgx_status);
    }
    else
    {
        printf_info(felog, "Verify secret successfully!\n");
    }

    ecall_ra_close(this->enclave_id, &sgx_status, this->ra_context);

    return "successfully";
}

/**
 * @description: Process registry request
 * @param req -> Http request content
 * */
void MessageHandler::process(web::http::http_request &req)
{
    string content = req.extract_utf8string().get();
    printf("content: %s\n", content.c_str());
    json::JSON req_json = json::JSON::Load(content);
    string type = req_json["type"].ToString();

    if(type.compare("register") == 0)
    {
    }
    else if(type.compare("msg0") == 0)
    {
        string msg1 = handle_att_msg0();
        req.reply(web::http::status_codes::OK, msg1);
    }
    else if(type.compare("msg2") == 0)
    {
        string msg3 = handle_att_msg2(content);
        req.reply(web::http::status_codes::OK, msg3);
    }
    else if(type.compare("msg4") == 0)
    {
        string msg5 = handle_att_msg4(content);
        req.reply(web::http::status_codes::OK, "successfully");
    }
    else
    {
        printf_err(felog, "Unknown message type!\n");
        req.reply(web::http::status_codes::OK, "successfully");
    }
}
