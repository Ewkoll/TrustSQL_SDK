/*!
 * date:    8/14/2017
 * Contact: uckzou@tencent.com
 */
#include "chttp.h"

#include <curl/curl.h>


chttp_request::chttp_request(chttp_type type)
{
    this->type = type;
}

chttp_response::chttp_response()
{
    rescode = 0;
}

bool chttp_response::is_successed() const
{
    return rescode == 200;
}

chttp_client::chttp_client()
{
    static CURLcode ci = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (ci) {
    }

    pcurl = NULL;

    timeout_read = 0;
    timeout_connect = 0;
    verbose = 0;
    keep_alive = 0;
    keep_idle = 0;
    keep_intvl = 0;
}

chttp_client::~chttp_client()
{
    if (pcurl != NULL) {
        curl_easy_cleanup(pcurl);
        pcurl = NULL;
    }
}

const std::string& chttp_client::get_last_error() const
{
    return error;
}

static size_t curl_write_func(char* ptr, size_t size, size_t nmemb, std::string* s)
{
    s->append(ptr, size * nmemb);

    return size * nmemb;
}

int chttp_client::perform(const chttp_request& request, chttp_response& response)
{
    int rc = CURLE_FAILED_INIT;
    char error_buffer[CURL_ERROR_SIZE] = { 0 };
    curl_slist *headers = NULL;
    do {
        if (pcurl == NULL) {
            if ((pcurl = curl_easy_init()) == NULL) {
                break;
            }
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_ERRORBUFFER, error_buffer)) != CURLE_OK) {
            break;
        }
        if (timeout_read != 0) {
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_TIMEOUT_MS, timeout_read)) != CURLE_OK) {
                break;
            }
        }
        if (timeout_connect != 0) {
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_CONNECTTIMEOUT, timeout_connect)) != CURLE_OK) {
                break;
            }
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_NOSIGNAL, 1L)) != CURLE_OK) {
            break;
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_SSL_VERIFYPEER, ca_path.empty() ? 0L : 1L)) != CURLE_OK) {
            break;
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_SSL_VERIFYHOST, ca_path.empty() ? 0L : 2L)) != CURLE_OK) {
            break;
        }
        if (!ca_path.empty())
        {
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_CAINFO, ca_path.c_str())) != CURLE_OK) {
                break;
            }
        }
        if (!cookie_file.empty()) {
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_COOKIEFILE, cookie_file.c_str())) != CURLE_OK) {
                break;
            }
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_COOKIEJAR, cookie_file.c_str())) != CURLE_OK) {
                break;
            }
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_VERBOSE, verbose)) != CURLE_OK) {
            break;
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_PROXY, proxy.c_str())) != CURLE_OK) {
            break;
        }
        if (keep_alive != 0)
        {
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_TCP_KEEPALIVE, 1L)) != CURLE_OK) {
                break;
            }
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_TCP_KEEPIDLE, keep_idle)) != CURLE_OK) {
                break;
            }
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_TCP_KEEPINTVL, keep_intvl)) != CURLE_OK) {
                break;
            }
        }
        for (std::map<std::string, std::string>::const_iterator it = request.headers.begin(); it != request.headers.end(); ++it) {
            headers = curl_slist_append(headers, std::string(it->first + ": " + it->second).c_str());
        }
        if (headers != NULL) {
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_HTTPHEADER, headers)) != CURLE_OK) {
                break;
            }
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_URL, request.url.c_str())) != CURLE_OK) {
            break;
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_HEADERFUNCTION, curl_write_func)) != CURLE_OK) {
            break;
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_HEADERDATA, &response.headers)) != CURLE_OK) {
            break;
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_WRITEFUNCTION, curl_write_func)) != CURLE_OK) {
            break;
        }
        if ((rc = curl_easy_setopt(pcurl, CURLOPT_WRITEDATA, &response.data)) != CURLE_OK) {
            break;
        }
        if (request.type == chttp_get)
        {
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_FOLLOWLOCATION, true)) != CURLE_OK) {
                break;
            }
        }
        else if (request.type == chttp_post)
        {
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_POST, 1L)) != CURLE_OK) {
                break;
            }
            if (!request.data.empty())
            {
                if ((rc = curl_easy_setopt(pcurl, CURLOPT_POSTFIELDS, request.data.c_str())) != CURLE_OK) {
                    break;
                }
                if ((rc = curl_easy_setopt(pcurl, CURLOPT_POSTFIELDSIZE, request.data.length())) != CURLE_OK) {
                    break;
                }
            }
        }
        else if (request.type == chttp_put)
        {
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_CUSTOMREQUEST, "PUT")) != CURLE_OK) {
                break;
            }
            if (!request.data.empty())
            {
                if ((rc = curl_easy_setopt(pcurl, CURLOPT_POSTFIELDS, request.data.c_str())) != CURLE_OK) {
                    break;
                }
                if ((rc = curl_easy_setopt(pcurl, CURLOPT_POSTFIELDSIZE, request.data.length())) != CURLE_OK) {
                    break;
                }
            }
        }
        else if (request.type == chttp_delete)
        {
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_CUSTOMREQUEST, "DELETE")) != CURLE_OK) {
                break;
            }
            if ((rc = curl_easy_setopt(pcurl, CURLOPT_FOLLOWLOCATION, true)) != CURLE_OK) {
                break;
            }
        }
        if ((rc = curl_easy_perform(pcurl)) != CURLE_OK) {
            break;
        }
        if ((rc = curl_easy_getinfo(pcurl, CURLINFO_RESPONSE_CODE, &response.rescode)) != CURLE_OK) {
            break;
        }
    } while (0);

    if (keep_alive == 0 && pcurl != NULL) {
        curl_easy_cleanup(pcurl);
        pcurl = NULL;
    }
    if (headers != NULL) {
        curl_slist_free_all(headers);
    }

    error = error_buffer;

    return rc;
}
