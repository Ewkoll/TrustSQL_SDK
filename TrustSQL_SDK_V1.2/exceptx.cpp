/*!
 * ╔╦╦═╦═╦╦═╦╦═╦═╦═╦╦╗
 * ║║║═╣═╣║║║╬╬║═╣╬║║║
 * ╚═╩═╩╩╩╩╩═╩═╩═╩═╩═╝
 * date:    4/10/2017
 * Contact: uckzou@tencent.com
 */
#include "exceptx.h"

#include <string.h>

#if defined _WIN32
#include <windows.h>
#endif


size_t errstr(char* error, size_t len)
{
    int _eno =
#if defined _WIN32
        GetLastError();
    SetLastError(0);
#else
        errno;
#endif

    size_t _len = 0;
    if (_eno != 0) {
#if defined _WIN32
        _len = snprintf(error, len, ":errno(%u):error(", _eno);
        _len += ::FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM,
            0,
            _eno,
            MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
            error + _len,
            DWORD(len - _len),
            0);
        while (_len-- != 0) {
            if (error[_len] == '\r' || error[_len] == '\n') {
                error[_len] = 0;
            }
            else {
                break;
            }
        }
        if (_len < len) {
            error[++_len] = ')';
        }
        if (_len < len) {
            error[_len + 1] = 0;
        }
#else
        _len = snprintf(error, len, ":errno(%u):error(%s)", _eno, ::strerror(_eno));
#endif
    }
    return _len;
}
