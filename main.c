#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <libgen.h>
#include <sys/stat.h>
#include "http_server.h"
#include "coap_handler.h"
#include "coap_client.h"

static void cleanup() {
    fprintf(stderr, "Exiting...\n");
    if(coap_context) coap_free_context(coap_context); coap_context = NULL;
    if(http_daemon) MHD_stop_daemon(http_daemon); http_daemon = NULL;
}

struct sigaction old_action;
static void signal_handler(int sig_no)
{
    fprintf(stderr, "SIGINT received\n");
    cleanup();
    sigaction(SIGINT, &old_action, NULL);
    kill(0, SIGINT);
}

int main(int argc, char *argv[])
{
    int opt;
    str destination_hostname = {.length = 0, .s = NULL};
    uint16_t server_port = 8080, destination_port = COAP_DEFAULT_PORT;
    char *endptr;
    struct stat s;

    while((opt = getopt(argc, argv, "D:P:p:f:h")) != EOF) {
        switch(opt) {
            case 'D':
                destination_hostname.s = (unsigned char *)optarg;
                destination_hostname.length = strlen(optarg);
                resolve_address(&destination_hostname, (struct sockaddr *)&destination);
                break;
            case 'P':
                destination_port = (uint16_t)strtoul(optarg, &endptr, 10);
                if(*endptr != '\0') {
                    fprintf(stderr, "error: invalid port number: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                break;
            case 'p':
                server_port = (uint16_t)strtoul(optarg, &endptr, 10);
                if(*endptr != '\0') {
                    fprintf(stderr, "error: invalid port number: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                break;
            case 'f':
                if(stat(optarg, &s) == -1) {
                    if(ENOENT == errno) {
                        /* does not exist */
                        fprintf(stderr, "error: %s: %s\n", optarg, strerror(errno));
                        return EXIT_FAILURE;
                    }
                    else {
                        perror("stat");
                        return EXIT_FAILURE;
                    }
                } else {
                    if(S_ISDIR(s.st_mode)) {
                        /* it's a dir */
                        strncpy(static_files_path, optarg, 64);
                        fprintf(stderr, "Will serve static files of directory '%s'\n", static_files_path);
                    }
                    else {
                        /* exists but is no dir */
                        fprintf(stderr, "error: %s is not a directory\n", optarg);
                        return EXIT_FAILURE;
                    }
                }
                break;
            case 'h':
                fprintf(stderr, "usage: %s -D coap_host [-P coap_port] [-p HTTP_server_port] [-f static_files_dir]\n",
                        basename(argv[0]));
                return EXIT_SUCCESS;
            default:
                return EXIT_FAILURE;
        }
    }

    if(destination_hostname.s == NULL) {
        fprintf(stderr, "error: please specify the target coap host of the proxy with the -D option\n");
        return EXIT_FAILURE;
    }

    destination.sin_port = htons(destination_port);

    // Register the clean function for when the program exists
    if(atexit(cleanup) != 0) {
        perror("atexit");
        return EXIT_FAILURE;
    }
    // Also call it where a SIGINT is received
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &signal_handler;
    if(sigaction(SIGINT, &action, &old_action) != 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    start_http_server(server_port);
    if(http_daemon == NULL) {
        fprintf(stderr, "error: HTTP server failed to start: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    fprintf(stderr, "HTTP server is listening on port %u (using libmicrohttpd %s)\n", server_port, MHD_get_version());

    // Create the CoAP context
    coap_set_log_level(LOG_DEBUG);
    coap_context = coap_create_context("0.0.0.0", NULL);
    coap_register_response_handler(coap_context, coap_response_handler);

    // Now let microhttpd accept HTTP requests and wait for a signal
    pause();

    return EXIT_SUCCESS;
}