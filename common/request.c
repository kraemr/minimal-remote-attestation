#include "request.h"

size_t write_callback(void *data, size_t size, size_t nmemb, void *userp) {
    size_t real_size = size * nmemb;
    char **response_ptr = (char **)userp;
//    *response_ptr = realloc(*response_ptr, strlen(*response_ptr) + real_size + 1);
   // if (*response_ptr == NULL) return 0;
    strncat(*response_ptr, data, real_size);
    return real_size;
}

void initCurl() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

// Responses are always very small for our use case
char *sendPostCbor(const char *url, const void *cbor_data, size_t cbor_len,char response[4096]) {
    CURL *curl = curl_easy_init();
    CURLcode res;
    if (!curl || !response) return NULL;
    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, "Content-Type: text/plain");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cbor_data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)cbor_len);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "libcurl error: %s\n", curl_easy_strerror(res));
        free(response);
        response = NULL;
    }
    printf("res: %s ", response);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}