#include "request.h"

struct cb_data {
    char *buf;
    size_t size;
};

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t total = size * nmemb;

    struct cb_data *data = (struct cb_data *)userdata;

    if (data->size + total >= 4096)
        return 0;

    memcpy(data->buf + data->size, ptr, total);
    data->size += total;

    return total;
}

void initCurl() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

// Responses are always very small for our use case
char * sendPostCbor(
    const char *url, 
    const void *cbor_data, 
    size_t cbor_len,
    char response[4096],
    const char* session_id,
    size_t* response_size)
{
    CURL *curl = curl_easy_init();
    CURLcode res;
    if (!curl || !response) return NULL;
    struct curl_slist *headers = NULL;
    char session_header[256];
    snprintf(session_header, sizeof(session_header),
             "X-Session-Id: %s", session_id);
    headers = curl_slist_append(headers, "Content-Type: application/cbor");
    headers = curl_slist_append(headers, session_header);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cbor_data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)cbor_len);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    struct cb_data data = {
        .buf = response,
        .size = 0
    };
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
    
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "libcurl error: %s\n", curl_easy_strerror(res));
        response = NULL;
    }
    double downloaded = 0;
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &downloaded);
    *response_size = (size_t)downloaded;
    
    //printf("res: %s ", response);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

int sendStringWithSession(const char *url, const char *payload, const char *session_id)
{
    CURL *curl;
    CURLcode res = CURLE_FAILED_INIT;

    if (!url || !payload || !session_id)
        return 0;

    curl = curl_easy_init();
    if (!curl)
        return 0;

    struct curl_slist *headers = NULL;

    char session_header[256];
    snprintf(session_header, sizeof(session_header),
             "X-Session-Id: %s", session_id);

    headers = curl_slist_append(headers, "Content-Type: text/plain");
    headers = curl_slist_append(headers, session_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);

    res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        return 0;
    }

    return (http_code == 200) ? 1 : 0;
}
