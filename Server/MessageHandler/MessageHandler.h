#ifndef _MESSAGEHANDLER_H_
#define _MESSAGEHANDLER_H_

#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <iostream>
#include <inttypes.h>
#include <string>
#include <map>
#include <cpprest/http_listener.h>
#include "sgx_tseal.h"
#include "Enclave_u.h"
// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"
// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "Utils.h"

#define ENCLAVE_PATH "enclave.signed.so"

using namespace std;

class MessageHandler {
    public:
        void process(web::http::http_request &req);
        MessageHandler();
    private:
        sgx_status_t init_enclave();
        std::string handle_att_msg0();
        std::string handle_att_msg2(std::string msg2_str);
        std::string handle_att_msg4(std::string msg4_str);
        void handle_register();
        
        sgx_enclave_id_t enclave_id;
        sgx_ra_context_t ra_context;
        web::http::client::http_client *client;
        map<vector<uint8_t>, string> accid_phone_map;
};

#endif
