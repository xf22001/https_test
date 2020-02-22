#include <stdio.h>
#include <string.h>
#include "https.h"
#include <stdlib.h>

void *calloc_1(size_t nmemb, size_t size);
void free_1(void *ptr);
static void *my_calloc(size_t nmemb, size_t size)
{
	void *ptr = calloc_1(nmemb, size);

	return ptr;
}

static my_free(void *ptr)
{
	free_1(ptr);
}

int main(int argc, char *argv[])
{
    char *url;
    char data[1024], response[4096];
    int  i, ret, size;

    HTTP_INFO hi1, hi2;

    //mbedtls_platform_set_calloc_free(calloc, free);
    mbedtls_platform_set_calloc_free(calloc_1, free_1);

    // Init http session. verify: check the server CA cert.
    http_init(&hi1, FALSE);
    http_init(&hi2, TRUE);

/*
    url = "https://localhost:8080/upload";
    sprintf(data,
            "--1234567890abcdef\r\n"
            "Content-Disposition: form-data; name=\"upload\"; filename=\"test.txt\"\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "test message\r\n"
            "--1234567890abcdef--\r\n\r\n"
    );

    ret = http_post(&hi1, url, data, response, sizeof(response));

    printf("return code: %d \n", ret);
    printf("return body: %s \n", response);
*/

    /*
    url = "https://localhost:8080/upload";

    if(http_open(&hi1, url) < 0)
    {
        http_strerror(data, 1024);
        printf("socket error: %s \n", data);

        goto error;
    }

    //snprintf(hi1.request.method, 8, "POST");
    snprintf(hi1.request.method, 8, "GET");
    hi1.request.close = FALSE;
    hi1.request.chunked = FALSE;
    snprintf(hi1.request.content_type, 256, "multipart/form-data; boundary=1234567890abcdef");

    size = sprintf(data,
                   "--1234567890abcdef\r\n"
                   "Content-Disposition: form-data; name=\"upload\"; filename=\"test.txt\"\r\n"
                   "Content-Type: text/plain\r\n\r\n"
                   "test message\r\n"
                   "--1234567890abcdef--\r\n"
                   );

    hi1.request.content_length = size;

    if(http_write_header(&hi1) < 0)
    {
        http_strerror(data, 1024);
        printf("socket error: %s \n", data);

        goto error;
    }

    if(http_write(&hi1, data, size) != size)
    {
        http_strerror(data, 1024);
        printf("socket error: %s \n", data);

        goto error;
    }

    // Write end-chunked
    if(http_write_end(&hi1) < 0)
    {
        http_strerror(data, 1024);
        printf("socket error: %s \n", data);

        goto error;
    }

    ret = http_read_chunked(&hi1, response, sizeof(response));

    printf("return code: %d \n", ret);
    printf("return body: %s \n", response);
    */

    url = "https://httpbin.org/get";
    ret = http_get(&hi2, url, response, sizeof(response));

    printf("return code: %d \n", ret);
    printf("return body: %s \n", response);


/*
    // Test a http get method.
    url = "http://httpbin.org/get?message=https_client";

    ret = http_get(&hi1, url, response, sizeof(response));

    printf("return code: %d \n", ret);
    printf("return body: %s \n", response);

    // Test a http post method.

    url = "http://httpbin.org/post";
    sprintf(data, "{\"message\":\"Hello, https_client!\"}");

    ret = http_post(&hi1, url, data, response, sizeof(response));

    printf("return code: %d \n", ret);
    printf("return body: %s \n", response);

    // Test a https get method.

    url = "https://httpbin.org/get?message=https_client";

    ret = http_get(&hi2, url, response, sizeof(response));

    printf("return code: %d \n", ret);
    printf("return body: %s \n", response);

    // Test a https post method.

    url = "https://httpbin.org/post";
    sprintf(data, "{\"message\":\"Hello, https_client!\"}");

    ret = http_post(&hi2, url, data, response, sizeof(response));

    printf("return code: %d \n", ret);
    printf("return body: %s \n", response);

    // Test a https post with the chunked-encoding data.

    url = "https://httpbin.org/post";

    if(http_open_chunked(&hi2, url) == 0)
    {
        size = sprintf(data, "[{\"message\":\"Hello, https_client %d\"},", 0);

        if(http_write_chunked(&hi2, data, size) != size)
        {
            http_strerror(data, 1024);
            printf("socket error: %s \n", data);

            goto error;
        }

        for(i=1; i<4; i++)
        {
            size = sprintf(data, "{\"message\":\"Hello, https_client %d\"},", i);
            if(http_write_chunked(&hi2, data, size) != size)
            {
                http_strerror(data, 1024);
                printf("socket error: %s \n", data);

                goto error;
            }
        }

        size = sprintf(data, "{\"message\":\"Hello, https_client %d\"}]", i);
        if(http_write_chunked(&hi2, data, strlen(data)) != size)
        {
            http_strerror(data, 1024);
            printf("socket error: %s \n", data);

            goto error;
        }

        ret = http_read_chunked(&hi2, response, sizeof(response));

        printf("return code: %d \n", ret);
        printf("return body: %s \n", response);

    }
    else
    {
        http_strerror(data, 1024);
        printf("socket error: %s \n", data);
    }

    error:
*/

error:

    http_close(&hi1);
    http_close(&hi2);

    return 0;
}
