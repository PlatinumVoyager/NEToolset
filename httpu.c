// #ifndef _GNU_SOURCE
// #define _GNU_SOURCE
// #endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
#include <locale.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
// #include <linux/ip.h>
#include <arpa/inet.h>

#define SSDP_SCOPE_MULTICAST_PORT 1900
#define SSDP_SCOPE_MULTICAST_ADDR "239.255.255.250"

#define BLUE_OK "[\033[0;34m*\033[0;m]"
#define GREEN_OK "[\033[0;32m+\033[0;m]"
#define RED_ERR "[\033[0;31m!\033[0;m]"


void httpu_sig_handler(int sigint);

int UNICAST_RESPONSES = 0;


int main(void)
{
    srand(time(NULL));
    setlocale(LC_ALL, "");

    if (signal(SIGINT, httpu_sig_handler) == SIG_ERR)
    {
        fprintf(stderr, "%s ERROR: Failed setting up main interrupt handler: main() => signal(SIGINT, httpu_sig_handler)!\n", RED_ERR);

        return -1;
    }

    // client structure for multicast group (SSDP)
    struct sockaddr_in client_mcast_opts;

    // UDP control point = client
    int client_multicast_sock = 0;
    int src_port = (rand() % (65535 - 1024) + 1024); // set random source port to bind socket to

    printf("%s Set client multicast socket port opt => %d\n", GREEN_OK, src_port);

    client_mcast_opts.sin_family = AF_INET;
    client_mcast_opts.sin_port = htons((uint16_t)src_port);
    client_mcast_opts.sin_addr.s_addr = INADDR_ANY;

    // setup socket structure for multicast target
    struct sockaddr_in scope_multicast_addr;

    scope_multicast_addr.sin_family = AF_INET;
    scope_multicast_addr.sin_port = htons(SSDP_SCOPE_MULTICAST_PORT);
    scope_multicast_addr.sin_addr.s_addr = inet_addr(SSDP_SCOPE_MULTICAST_ADDR);


    // might have to utf-8 (mutli-byte string) encode snprintf buffer
    const wchar_t *msg[] = {
        L"M-SEARCH * HTTP/1.1\r\n",
        L"HOST:239.255.255.250:1900\r\n",
        L"ST:ssdp:all\r\n",
        L"MX:120\r\n",
        L"MAN:\"ssdp:discover\"\r\n",
        L"\r\n"
    };

    size_t len = 0;
    size_t msg_size = (sizeof(msg) / sizeof(msg[0]));

    int buffer_len = 0;

    if ((client_multicast_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        fprintf(stderr, "%s ERROR: Setting up UDP socket for multicast UDP discovery request!\n", RED_ERR);

        return -1;
    }

    // set socket timeout opts
    struct timeval timeout;

    timeout.tv_sec = 120; // 2 minutes
    timeout.tv_usec = 0;

    printf("%s Setup UDP socket for multicast scope discovery request successfully...\n\n", GREEN_OK);

    // set data no receive socket timeout opt
    if (setsockopt(client_multicast_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1)
    {
        fprintf(stderr, "%s ERROR: Failed to set timeout setsockopt operation on the targeted socket!\n", RED_ERR);

        return -1;
    }

    // obtain proper size of 'msg' utf-8
    for (size_t i = 0; i < msg_size; i++)
    {
        // each array element of msg
        // set the length of the character string via wide str (typecast)
        len += wcslen(msg[i]);
    }

    char buffer[len * MB_CUR_MAX + 1];
    buffer[0] = '\0';

    // convert wchar_t to multibyte string, store converted chars into new buffer
    for (size_t t = 0; t < msg_size; t++)
    {
        // convert each array element (wide character string) to a utf-8 multibyte string
        // before sending it over the wire
        wcstombs(buffer + strlen(buffer), msg[t], len * MB_CUR_MAX + 1);
    }

    printf("%s Sending target message:\n\"\n", BLUE_OK);
    printf("%s", buffer);
    printf("\"\nto scope multicast address %s:%d\n", SSDP_SCOPE_MULTICAST_ADDR, SSDP_SCOPE_MULTICAST_PORT);

    printf("\nPress <ENTER> to send device traffic relay...\n");
    getchar();

    buffer_len = strlen(buffer);

    // send more than 1 M-SEARCH discover message from root control point (operator device)
    for (int i = 0; i < 5;)
    {
        // use the locally bound UDP socket, pass the message buffer, along with the length, no flags given, send the data
        // to the remote target, along with the size of the struct
        if (sendto(client_multicast_sock, buffer, buffer_len, 0, (struct sockaddr*)&scope_multicast_addr, sizeof(scope_multicast_addr)) == -1)
        {
            fprintf(stderr, "%s ERROR: Failed to send data to scope multicast address for SSDP discovery operations...\n", RED_ERR);

            return -1;
        }

        i++;
        printf("%s SENT HTTPU SSDP M-SEARCH MESSAGE TO MULTICAST SCOPE ADDRESS #%d\n", GREEN_OK, i);
    }

    printf("\n");
    
    char resp_buffer[8000];

    struct sockaddr_in sender_addr;
    socklen_t sender_addr_len = sizeof(sender_addr);

    while (1)
    {
        // obtain data from the network interface card through the locally bound UDP socket
        // include the allocated space (resp_buffer) via a buffer to hold the retrieved data
        // no flags, pass a structure 'sender_addr', along with the size
        int bytes_recv = recvfrom(client_multicast_sock, resp_buffer, sizeof(resp_buffer), 0, (struct sockaddr *)&sender_addr, &sender_addr_len); 

        if (bytes_recv == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                printf("%s Got setsockopt set timeout interval reached...\n", BLUE_OK);

                break;
            }
            else 
            {
                fprintf(stderr, "%s ERROR: Failed to obtain data from unicast network traffic.\n", RED_ERR);
            }
        }
        else
        {
            // buffer to store converted internet protocol address 'sender_addr.sin_addr'
            char response_host[INET_ADDRSTRLEN];

            // convert the structural address type (binary) to a presentational format 
            inet_ntop(AF_INET, &(sender_addr.sin_addr), response_host, INET_ADDRSTRLEN);

            resp_buffer[bytes_recv] = '\0'; // null terminate received data
            printf("\033[0;32m%s:%d\033[0;m => %s\n", response_host, sender_addr.sin_port, resp_buffer);

            UNICAST_RESPONSES++;
        }
    }

    close(client_multicast_sock);

    printf("%s %d Unicast discover responses confirmed.\n", GREEN_OK, UNICAST_RESPONSES);
    printf("\n%s Socket closed successfully.\n", BLUE_OK);


    return 0;
}


void httpu_sig_handler(int sigint)
{
    // find method to close socket
    printf("\n%s Got interrupt (SIG_INT)\n", BLUE_OK);
    printf("%s %d Unicast discover responses confirmed.\n", GREEN_OK, UNICAST_RESPONSES);

    exit(0);
}