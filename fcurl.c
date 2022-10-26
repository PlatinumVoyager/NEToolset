#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <curl/curl.h>

#define FCURL_VERSION "1.0 Beta"

#define SOCKS5_PROXY_FQDN "https://www.ifconfig.me"
#define TORSOCKS5_HOST_PROXY "127.0.0.1:9050"

struct string {
    char *ptr;
    size_t len;
};

void display_help(void);
int init_curl(char *URL, bool proxy);
void init_string(struct string *s);

size_t write_func(void *ptr, size_t size, size_t nmemb, struct string *s);


int main(int argc, char *argv[])
{
    int opt;
    bool proxy = NULL;

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"noproxy", no_argument, NULL, 'n'},
        {"torify", no_argument, NULL, 't'}
    };

    const char *short_options = "hnt";

    if (argc < 2) {
        display_help();

        return EXIT_FAILURE;
    }

    int option_index = 0;
    while ((opt = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
    {
        switch (opt)
        {
            case 'h':
            {
                display_help();
                exit(0);
            }

            case 'n':
            {
                printf("INFO: **exec => \"noproxy\"\nSTATUS: Not setting up proxy: set proxy = \"false\"\n\n");
                proxy = false;

                break;
            }

            case 't':
            {
                printf("INFO: **exec => \"torify\"\nSTATUS: Setting up socks5 proxy: %s\n\n", TORSOCKS5_HOST_PROXY);
                proxy = true;

                break;
            }

            default:
            {
                proxy = true;
                break;
            }
        }
    }

    printf("Press <ENTER> to continue, CTRL+C to cancel request...\n");
    getchar();

    init_curl(SOCKS5_PROXY_FQDN, proxy);

    return 0;
}


int init_curl(char *URL, bool proxy)
{
    CURL *curl;
    CURLcode retcode;

    curl = curl_easy_init();

    if (curl) 
    { 
        struct string s;
        init_string(&s);

        curl_easy_setopt(curl, CURLOPT_URL, URL); 
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
        
        if (proxy == true)
        {
            curl_easy_setopt(curl, CURLOPT_PROXY, TORSOCKS5_HOST_PROXY);
            curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
        }

        retcode = curl_easy_perform(curl);

        if (retcode != CURLE_OK) {
            fprintf(stderr, "./fcurl >> error: %s\n", curl_easy_strerror(retcode));

            return EXIT_FAILURE;
        }

        printf("Your IP: \033[0;32m%s\033[0;m\n", s.ptr);
        free(s.ptr);

        curl_easy_cleanup(curl);
    }

    return 0;
}


void init_string(struct string *s)
{
    s->len = 0;
    s->ptr = malloc(s->len + 1);

    if (s->ptr == NULL)
    {
        fprintf(stderr, "failed to allocate: malloc()\n");
        exit(EXIT_FAILURE);
    }

    s->ptr[0] = '\0';
}


size_t write_func(void *ptr, size_t size, size_t nmemb, struct string *s)
{
    size_t new_len = s->len + size * nmemb;
    s->ptr = realloc(s->ptr, new_len + 1);

    if (s->ptr == NULL)
    {
        fprintf(stderr, "failed to reallocate: realloc()\n");

        return EXIT_FAILURE;
    }

    memcpy(s->ptr + s->len, ptr, size * nmemb);

    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size * nmemb;
}


void display_help(void)
{
    char t = '=';
    char underline[BUFSIZ];
    char *str = "** USAGE: ./fcurl <options>";
    
    printf("fcurl: %s\nQuery external $SOCKS5_PROXY_FQDN to identify link-global address\n\n%s\n",
        FCURL_VERSION, str);

    for (int i = 0; i < strlen(str); i++)
    {
        underline[i] = t;
        
        if (underline[i] == '\0')
        {
            break;
        }
    }
    
    printf("%s\n", underline);
    
    printf(
    "-h/--help\t\tdisplay this help message and exit\n"
    "-n/--noproxy\t\tdisable proxy support\n"
    "-t/--torify\t\tuse tor socks5 proxy to execute request (default: socks5://127.0.0.1:9050)\n"
    );
}
