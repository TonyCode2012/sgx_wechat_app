#include "App.h"
#include "Common.h"
#include "Logfile.h"

extern FILE *felog;

//int main(int argc, char** args)
int main()
{
    // Create log file
    if ((felog = create_logfile("./server.log")) == NULL)
    {
        printf_err(NULL, "Create log file failed!\n");
        return -1;
    }

    //WebService *ws = new WebService("http://127.0.0.0:12345");
    WebService *ws = new WebService("http://localhost:12345");
    MessageHandler *msg_handler = new MessageHandler();
    ws->set_msg_handler(msg_handler);
    ws->start();
    while(true)
    {
        sleep(3);
        //printf("Waiting for new connection.\n");
    }
    return 1;
}
