#include "MessageHandler.h"
#include "Json.hpp"

using namespace std;


MessageHandler::MessageHandler()
{
    //this->client = new web::http::client::http_client(U("http://localhost:12345"));
    init_enclave();
}

sgx_status_t MessageHandler::init_enclave()
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_status_t ra_status = SGX_SUCCESS;
    int launch_token_update = 0;
    int enclave_lost_sgx_statusry_time = 1;
    sgx_launch_token_t launch_token = {0};

    memset(&launch_token, 0, sizeof(sgx_launch_token_t));

    do {
        sgx_status = sgx_create_enclave(ENCLAVE_PATH,
                                        SGX_DEBUG_FLAG,
                                        &launch_token,
                                        &launch_token_update,
                                        &this->enclave_id,
                                        NULL);
        printf("enclave_id:%" PRIu64 "\n",this->enclave_id);

        if (SGX_SUCCESS != sgx_status) 
        {
            //Log("Error, call sgx_create_enclave fail! ErrorCode:%lx", log::error, sgx_status);
            //print_error_message(sgx_status);
            break;
        } 
        else 
        {
            //Log("Call sgx_create_enclave success");

            sgx_status = ecall_init_ra(this->enclave_id,
                                       &ra_status,
                                       false,
                                       &this->ra_context);
        }

    } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_sgx_statusry_time--);

    if (sgx_status == SGX_SUCCESS)
    {
        //Log("Enclave created, ID: %llx", this->enclave_id);
    }


    return sgx_status;
}

string MessageHandler::handle_att_msg0()
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_ra_msg1_t ra_msg1;
    int retry = 5;
    json::JSON msg1_json;

    do {
        sgx_status = sgx_ra_get_msg1(this->ra_context,
                                     this->enclave_id,
                                     sgx_ra_get_ga,
                                     &ra_msg1);

        if(SGX_SUCCESS == sgx_status)
        {
            break;
        }
        
        if (SGX_ERROR_BUSY == sgx_status) 
        {
            if (retry > 0) 
            { //retried 5 times, so fail out
                //Log("Error, sgx_ra_get_msg1 is busy - 5 retries failed", log::error);
                break;;
            }
            else 
            {
                sleep(3);
                retry--;
            }
        } 
        else 
        {    //error other than busy
            //Log("Error, failed to generate MSG1,error code:%lx", sgx_status, log::error);
            break;
        }
    } while(true);

    /* Assemble msg1 */
    msg1_json["gax"] = hexstring(switch_endian(ra_msg1.g_a.gx,sizeof(ra_msg1.g_a.gx)), sizeof(ra_msg1.g_a.gx));
    msg1_json["gay"] = hexstring(switch_endian(ra_msg1.g_a.gy,sizeof(ra_msg1.g_a.gy)), sizeof(ra_msg1.g_a.gy));
    msg1_json["gid"] = hexstring(switch_endian(ra_msg1.gid,sizeof(ra_msg1.gid)), sizeof(ra_msg1.gid));
    //msg1_json["gid"] = string(base64_encode((char*)ra_msg1.gid, sizeof(ra_msg1.gid)));

    return msg1_json.dump();
}

void MessageHandler::assemble_msg2(string msg2_str, sgx_ra_msg2_t *p_msg2)
{
    json::JSON msg2_json = json::JSON::Load(msg2_str);
    const char* gbx = msg2_json["gbx"].ToString().c_str();
    const char* gby = msg2_json["gby"].ToString().c_str();
    const char* spid = msg2_json["spid"].ToString().c_str();
    const char* quote_type = msg2_json["quoteType"].ToString().c_str();
    const char* kdf_id = msg2_json["kdfId"].ToString().c_str();
    const char* sigSP_x = msg2_json["SigSPX"].ToString().c_str();
    const char* sigSP_y = msg2_json["SigSPY"].ToString().c_str();
    const char* cmac_smk = msg2_json["CMACsmk"].ToString().c_str();
    printf("=============== 1 SGX_ECP256_KEY_SIZE:%d\n",SGX_ECP256_KEY_SIZE);
    memcpy(p_msg2->g_b.gx, hex_string_to_bytes(gbx, SGX_ECP256_KEY_SIZE*2), SGX_ECP256_KEY_SIZE);
    memcpy(p_msg2->g_b.gy, hex_string_to_bytes(gby, SGX_ECP256_KEY_SIZE*2), SGX_ECP256_KEY_SIZE);
    printf("=============== 2\n");
    memcpy(&p_msg2->spid, hex_string_to_bytes(spid, 16*2), 16);
    memcpy(&p_msg2->quote_type, hex_string_to_bytes(quote_type, 2*2), 2);
    memcpy(&p_msg2->kdf_id, hex_string_to_bytes(kdf_id, 2*2), 2);
    printf("=============== quote_type:%hu\n",p_msg2->quote_type);
    printf("=============== kdf_id:%hu\n",p_msg2->kdf_id);
    printf("=============== 3 ecp256 size:%d\n",SGX_NISTP_ECP256_KEY_SIZE);
    memcpy(p_msg2->sign_gb_ga.x, hex_string_to_bytes(sigSP_x, 32*2), 32);
    memcpy(p_msg2->sign_gb_ga.y, hex_string_to_bytes(sigSP_y, 32*2), 32);
    printf("=============== 4 macsize:%d\n",SGX_MAC_SIZE);
    memcpy(&p_msg2->mac, hex_string_to_bytes(cmac_smk, SGX_MAC_SIZE*2), SGX_MAC_SIZE);
    p_msg2->sig_rl_size = 0;
}


string MessageHandler::handle_att_msg2(string msg2_str)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_ra_msg2_t *p_msg2 = (sgx_ra_msg2_t*)malloc(sizeof(sgx_ra_msg2_t));
    memset(p_msg2, 0, sizeof(sgx_ra_msg2_t));
    uint32_t msg2_size;
    assemble_msg2(msg2_str,p_msg2);

    sgx_ra_msg3_t *p_msg3 = NULL;
    uint32_t msg3_size;
    int retry = 3;

    do {
        sgx_status = sgx_ra_proc_msg2(this->ra_context,
                                      this->enclave_id,
                                      sgx_ra_proc_msg2_trusted,
                                      sgx_ra_get_msg3_trusted,
                                      p_msg2,
                                      sizeof(sgx_ra_msg2_t),
                                      &p_msg3,
                                      &msg3_size);
    } while (SGX_SUCCESS != sgx_status && --retry > 0);

    if(SGX_SUCCESS != sgx_status)
    {
        printf("[ERROR] sgx process msg2 failed:%lx\n",sgx_status);
    }

    return "msg3";
}

void MessageHandler::process(web::http::http_request &req)
{
    string content = req.extract_utf8string().get();
    printf("content: %s\n", content.c_str());
    json::JSON req_json = json::JSON::Load(content);
    string type = req_json["type"].ToString();

    if(type.compare("msg0") == 0)
    {
        string msg1 = handle_att_msg0();
        req.reply(web::http::status_codes::OK, msg1);
    }
    else if(type.compare("msg2") == 0)
    {
        string msg3 = handle_att_msg2(content);
        req.reply(web::http::status_codes::OK, msg3);
    }
}
