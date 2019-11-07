/*!
 * ╔╦╦═╦═╦╦═╦╦═╦═╦═╦╦╗
 * ║║║═╣═╣║║║╬╬║═╣╬║║║
 * ╚═╩═╩╩╩╩╩═╩═╩═╩═╩═╝
 * date:    4/10/2017
 * Contact: uckzou@tencent.com
 */
#pragma once
#include <string>
#include <vector>


namespace util
{
    class strconv
    {
    public:
        enum class code_t
        {
            mbs,
            utf16,
            utf8,
        };

    public:
        strconv(code_t from, code_t to);

        std::string code(const std::string & src);
        std::string code(const char* src, size_t size);

    private:
        const code_t m_from;
        const code_t m_to;
    };

    void set_charset(const char* _charset);

    bool code_chk_u8(const void* src, size_t size);
    void code_mbs_u16(const void* src, size_t size, std::string & dest);
    void code_u16_mbs(const void* src, size_t size, std::string & dest);
    void code_u16_u8(const void* src, size_t size, std::string & dest);
    void code_u8_u16(const void* src, size_t size, std::string & dest);
    void code_mbs_u8(const void* src, size_t size, std::string & dest);
    void code_u8_mbs(const void* src, size_t size, std::string & dest);

    template<class _string_t>
    std::vector<_string_t> split(const _string_t & src, const char* chs);


    /*  Implement
     **/
    template<class _string_t>
    inline std::vector<_string_t> split(const _string_t & src, const char* chs)
    {
        std::vector<_string_t> ret;
        if (!src.empty()) {
            size_t fst = 0;
            size_t pos = 0;
            do {
                pos = src.find_first_of(chs, fst);
                if (pos == _string_t::npos) {
                    if (fst < src.size()) {
                        ret.push_back(src.substr(fst));
                    }
                    break;
                }
                else {
                    if (pos == fst) {
                        ++fst;
                    }
                    else {
                        ret.push_back(src.substr(fst, pos - fst));
                        fst = pos + 1;
                    }
                }
            } while (true);
        }

        return ret;
    }

}

