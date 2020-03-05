#include "WebService.h"

//using namespace web;
//using namespace web::http;
//using namespace web::http::experimental::listener;


WebService::WebService(utility::string_t url)
{
    this->listener = new web::http::experimental::listener::http_listener(url);
    this->listener->support(web::http::methods::POST, std::bind(&WebService::handle_post, this, std::placeholders::_1));
    this->listener->support(web::http::methods::GET, std::bind(&WebService::handle_get, this, std::placeholders::_1));
}

WebService::~WebService()
{
    delete this->listener;
}

void WebService::set_msg_handler(MessageHandler *msg_handler)
{
    this->msg_handler = msg_handler;
}

void WebService::start()
{
    this->listener->open().wait();
    printf("==== start webservice successfully\n");
}

void WebService::stop()
{
    this->listener->close().wait();
}

void WebService::handle_post(web::http::http_request req)
{
    printf("===== comming...\n");
    this->msg_handler->process(req);
}

void WebService::handle_get(web::http::http_request req)
{
    printf("===== comming...\n");
}
