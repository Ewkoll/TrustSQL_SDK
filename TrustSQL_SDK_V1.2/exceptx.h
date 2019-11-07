/*!
 * ╔╦╦═╦═╦╦═╦╦═╦═╦═╦╦╗
 * ║║║═╣═╣║║║╬╬║═╣╬║║║
 * ╚═╩═╩╩╩╩╩═╩═╩═╩═╩═╝
 * date:    4/10/2017
 * Contact: uckzou@tencent.com
 */
#pragma once
#include <stdio.h>
#include <stdexcept>


#if defined _STRINGIZE || defined _STRINGIZEX
#undef _STRINGIZE
#undef _STRINGIZEX
#endif
#define _STRINGIZEX(x) #x
#define _STRINGIZE(x) _STRINGIZEX(x)
#if defined __LINESTR__
#undef __LINESTR__
#endif
#define __LINESTR__ _STRINGIZE(__LINE__)

#define _except_(errstr, exceptx, ...) exceptx(errfmt(errstr, __FUNCTION__, "[" __FILE__ ":%s:" __LINESTR__ "][" #exceptx "]:" __VA_ARGS__))
#define _throwx_(errstr, exceptx, ...) throw _except_(errstr, exceptx, ##__VA_ARGS__)

#define except(exceptx, ...) _except_(errstr, exceptx, ##__VA_ARGS__)
#define throwx(exceptx, ...) _throwx_(errstr, exceptx, ##__VA_ARGS__)

extern size_t errstr(char* error, size_t len);

template<class ... _args_t>
inline std::string errfmt(size_t(*errstr)(char*, size_t), const char* _func_, const char* fmt, _args_t ... args)
{
    char error[4096] = { 0 };
    errstr(error, sizeof(error));

    std::string buf;
    size_t len = snprintf(nullptr, 0, fmt, _func_, args ...);
    if (len > 0) {
        buf.resize(len + 1);
        len = snprintf(&buf[0], buf.size(), fmt, _func_, args ...);
        if (len > 0 && buf[len - 1] == ':') {
            --len;
        }
        buf.resize(len);
    }

    return buf + error;
}

using std::logic_error;
using std::domain_error;
using std::invalid_argument;
using std::length_error;
using std::out_of_range;
using std::runtime_error;
using std::range_error;
using std::overflow_error;
using std::underflow_error;

