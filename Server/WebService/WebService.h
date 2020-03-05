#include <stdio.h>
#include <iostream>
#include <cpprest/http_listener.h>
#include <cpprest/uri.h>
#include "MessageHandler.h"

class WebService {
    public:
        ~WebService();
        WebService(utility::string_t url);
        void set_msg_handler(MessageHandler *msg_handler);
        void start();
        void stop();
    private:
        void handle_post(web::http::http_request req);
        void handle_get(web::http::http_request req);
        web::http::experimental::listener::http_listener *listener;
        MessageHandler *msg_handler;
};
