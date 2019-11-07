/*!
 * date:    8/14/2017
 * Contact: uckzou@tencent.com
 */
#pragma once
#include <map>
#include <string>


enum chttp_type
{
    chttp_get,
    chttp_post,
    chttp_put,
    chttp_delete,
};

class chttp_request
{
public:
    chttp_request(chttp_type type = chttp_get);

public:
    chttp_type type;

    std::string url;
    std::map<std::string, std::string> headers;
    std::string data;

};

class chttp_response
{
public:
    chttp_response();

    bool is_successed() const;

public:
    long rescode;

    std::string headers;
    std::string data;

};

class chttp_client
{
public:
    explicit chttp_client();
    virtual ~chttp_client();

    const std::string& get_last_error() const;

    int perform(const chttp_request& request, chttp_response& response);

public:
    std::string ca_path;
    std::string cookie_file;
    std::string proxy;

    long verbose;

    long timeout_read;      //millseconds
    long timeout_connect;   //seconds

    long keep_alive;
    long keep_idle;         //seconds
    long keep_intvl;        //seconds

private:
    void* pcurl;

    std::string error;

};


