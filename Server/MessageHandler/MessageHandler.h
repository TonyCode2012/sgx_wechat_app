#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <iostream>
#include <inttypes.h>
#include <string>
#include <cpprest/http_listener.h>
#include "sgx_tseal.h"
#include "Enclave_u.h"
// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"
// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "Utils.h"

#define ENCLAVE_PATH "enclave.signed.so"

class MessageHandler {
    public:
        void process(web::http::http_request &req);
        MessageHandler();
    private:
        std::string handle_att_msg0();
        std::string handle_att_msg2(std::string msg2_str);
        std::string handle_att_msg4(std::string msg4_str);
        void generate_att_msg1();
        void generate_att_msg3();
        void assemble_msg2(std::string msg2_str, sgx_ra_msg2_t *p_msg2);
        void handle_register();
        sgx_status_t init_enclave();
        
        sgx_enclave_id_t enclave_id;
        sgx_ra_context_t ra_context;
        web::http::client::http_client *client;
};
