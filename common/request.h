#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
extern size_t write_callback(void *data, size_t size, size_t nmemb, void *userp);
extern void initCurl();
char * sendPostCbor(
    const char *url, 
    const void *cbor_data, 
    size_t cbor_len,
    char response[4096],
    const char* session_id,
    size_t* response_size);
int sendStringWithSession(const char *url, const char *payload, const char *session_id);
