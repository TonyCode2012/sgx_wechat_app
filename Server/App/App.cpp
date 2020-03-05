#include "App.h"

int main(int argc, char** args)
{
    //WebService *ws = new WebService("http://127.0.0.0:12345");
    WebService *ws = new WebService("http://localhost:12345");
    MessageHandler *msg_handler = new MessageHandler();
    ws->set_msg_handler(msg_handler);
    ws->start();
    while(true)
    {
        sleep(3);
        printf("Waiting for new connection.\n");
    }
    return 1;
}
