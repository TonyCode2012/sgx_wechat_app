#include "WebService.h"
#include "Common.h"

//using namespace web;
//using namespace web::http;
//using namespace web::http::experimental::listener;

extern FILE *felog;


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
    printf_info(felog, "Start webservice successfully!\n");
}

void WebService::stop()
{
    this->listener->close().wait();
}

void WebService::handle_post(web::http::http_request req)
{
    printf_info(felog, "Request comming...\n");
    this->msg_handler->process(req);
}

void WebService::handle_get(web::http::http_request req)
{
    printf_info(felog, "Request comming...\n");
    this->msg_handler->process(req);
}
