/*!
 * ╔╦╦═╦═╦╦═╦╦═╦═╦═╦╦╗
 * ║║║═╣═╣║║║╬╬║═╣╬║║║
 * ╚═╩═╩╩╩╩╩═╩═╩═╩═╩═╝
 * date:    4/10/2017
 * Contact: uckzou@tencent.com
 */
#include "crypto.h"
#include "exceptx.h"

#include <memory>
#include <cctype>
#include <vector>
#include <iomanip>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#if !defined max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif
#if !defined min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

const static char c_b16[] = "0123456789abcdef";
const static char c_b58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const static char c_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const static char r_b64[128] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
};

typedef runtime_error crypto_error;

#define throwx_crypto(exceptx, ...) _throwx_([](char* error, size_t len) -> size_t {\
    unsigned long _eno = ERR_peek_last_error();                                     \
    size_t _len = 0;                                                                \
    if (_eno != 0) {                                                                \
        _len = snprintf(error, len, ":errno(%lu):error(", _eno);                    \
        ERR_error_string_n(_eno, error + _len, len - _len);                         \
        _len = strnlen(error, len);                                                 \
        if (_len < len) {                                                           \
            error[++_len] = ')';                                                    \
        }                                                                           \
        if (_len < len) {                                                           \
            error[_len + 1] = 0;                                                    \
        }                                                                           \
    }                                                                               \
    return _len;                                                                    \
}, exceptx, ##__VA_ARGS__)


crypto::buffer::buffer(crypto::buffer::code_t type) : m_type(type)
{
}

crypto::buffer::buffer(const std::string & data, crypto::buffer::code_t type) : m_type(type)
{
    assign(data.data(), data.size());
}

crypto::buffer::buffer(const char* data, size_t size, crypto::buffer::code_t type) : m_type(type)
{
    assign(data, size);
}

crypto::buffer::buffer(const crypto::buffer & _buffer) : m_type(_buffer.m_type)
{
    assign(_buffer.data(), _buffer.size());
}

crypto::buffer & crypto::buffer::operator=(const crypto::buffer & _buffer)
{
    m_type = _buffer.m_type;

    assign(_buffer.data(), _buffer.size());

    return *this;
}

void crypto::buffer::dump(std::ostream & ostr) const
{
    crypto::dump_bin(ostr, data(), size());
}

crypto::buffer::code_t crypto::buffer::type() const
{
    return m_type;
}

crypto::buffer & crypto::buffer::rand(size_t size)
{
    m_type = buffer::code_t::binary;

    resize(size);
    crypto::rand_bin((void*)data(), size);

    return *this;
}

crypto::buffer crypto::buffer::code(crypto::buffer::code_t type) const
{
    if (m_type == type) {
        return *this;
    }

    crypto::buffer dest(type);
    switch (m_type)
    {
    case crypto::buffer::code_t::binary:
        if (type == crypto::buffer::code_t::base16) {
            code_b_16(data(), size(), dest);
        }
        else if (type == crypto::buffer::code_t::base58) {
            code_b_58(data(), size(), dest);
        }
        else if (type == crypto::buffer::code_t::base64) {
            code_b_64(data(), size(), dest);
        }
        else {
            throwx(invalid_argument, "m_type(%d):type(%d)", m_type, type);
        }
        break;
    case crypto::buffer::code_t::base16:
        if (type == crypto::buffer::code_t::binary) {
            code_16_b(data(), size(), dest);
        }
        else if (type == crypto::buffer::code_t::base58) {
            std::string tmp;
            code_16_b(data(), size(), tmp);
            code_b_58(tmp.data(), tmp.size(), dest);
        }
        else if (type == crypto::buffer::code_t::base64) {
            std::string tmp;
            code_16_b(data(), size(), tmp);
            code_b_64(tmp.data(), tmp.size(), dest);
        }
        else {
            throwx(invalid_argument, "m_type(%d):type(%d)", m_type, type);
        }
        break;
    case crypto::buffer::code_t::base58:
        if (type == crypto::buffer::code_t::binary) {
            code_58_b(data(), size(), dest);
        }
        else if (type == crypto::buffer::code_t::base16) {
            std::string tmp;
            code_58_b(data(), size(), tmp);
            code_b_16(tmp.data(), tmp.size(), dest);
        }
        else if (type == crypto::buffer::code_t::base64) {
            std::string tmp;
            code_58_b(data(), size(), tmp);
            code_b_64(tmp.data(), tmp.size(), dest);
        }
        else {
            throwx(invalid_argument, "m_type(%d):type(%d)", m_type, type);
        }
        break;
    case crypto::buffer::code_t::base64:
        if (type == crypto::buffer::code_t::binary) {
            code_64_b(data(), size(), dest);
        }
        else if (type == crypto::buffer::code_t::base16) {
            std::string tmp;
            code_64_b(data(), size(), tmp);
            code_b_16(tmp.data(), tmp.size(), dest);
        }
        else if (type == crypto::buffer::code_t::base58) {
            std::string tmp;
            code_64_b(data(), size(), tmp);
            code_b_58(tmp.data(), tmp.size(), dest);
        }
        else {
            throwx(invalid_argument, "m_type(%d):type(%d)", m_type, type);
        }
        break;
    default:
        throwx(invalid_argument, "m_type(%d):type(%d)", m_type, type);
        break;
    }
    return dest;
}

crypto::buffer crypto::buffer::hash(crypto::hash_f func) const
{
    crypto::buffer dest(buffer::code_t::binary);
    func(data(), size(), dest);
    return dest;
}

crypto::data_ptr::data_ptr() : m_data(nullptr), m_size(0)
{
}

crypto::data_ptr::data_ptr(std::string & data) : m_data((void*)data.data()), m_size(data.size())
{
}

crypto::data_ptr::data_ptr(void* data, size_t size) : m_data(data), m_size(size)
{
}

crypto::data_ptr & crypto::data_ptr::operator=(std::string & data)
{
    m_data = (void*)data.data();
    m_size = data.size();

    return *this;
}

void crypto::data_ptr::dump(std::ostream & ostr) const
{
    if (m_data != nullptr) {
        crypto::dump_bin(ostr, m_data, m_size);
    }
}

void* & crypto::data_ptr::data()
{
    return m_data;
}

size_t & crypto::data_ptr::size()
{
    return m_size;
}

crypto::data_ptr::byte_t & crypto::data_ptr::operator[](size_t index)
{
    if (index >= m_size) {
        throwx(out_of_range, "index(%zu):size(%zu)", index, m_size);
    }

    return *((crypto::data_ptr::byte_t*)m_data + index);
}

crypto::ecdsa::ecdsa(const std::string & name)
{
    crypto::eckey_new(&m_eckey, name);
}

crypto::ecdsa::~ecdsa()
{
    crypto::eckey_free(m_eckey);
}

std::string crypto::ecdsa::name() const
{
    std::string name;
    crypto::eckey_get_name(m_eckey, name);
    return name;
}

void* crypto::ecdsa::eckey() const
{
    return m_eckey;
}

void crypto::ecdsa::set_prvkey(const crypto::buffer & prvkey)
{
    crypto::eckey_set_prvkey(m_eckey, prvkey.code(buffer::code_t::binary));
}

crypto::buffer crypto::ecdsa::get_prvkey() const
{
    crypto::buffer prvkey(buffer::code_t::binary);
    crypto::eckey_get_prvkey(m_eckey, prvkey);
    return prvkey;
}

void crypto::ecdsa::set_pubkey(const crypto::buffer & pubkey)
{
    crypto::eckey_set_pubkey(m_eckey, pubkey.code(buffer::code_t::binary));
}

crypto::buffer crypto::ecdsa::get_pubkey() const
{
    crypto::buffer pubkey(buffer::code_t::binary);
    crypto::eckey_get_pubkey(m_eckey, pubkey);
    return pubkey;
}

void crypto::ecdsa::com_pubkey()
{
    crypto::eckey_com_pubkey(m_eckey);
}

void crypto::ecdsa::generate()
{
    crypto::eckey_generate(m_eckey);
}

bool crypto::ecdsa::check() const
{
    return eckey_check(m_eckey);
}

crypto::buffer crypto::ecdsa::sign(const std::string & data) const
{
    crypto::buffer signature(buffer::code_t::binary);
    eckey_sign(m_eckey, data, signature);
    return signature;
}

bool crypto::ecdsa::verify(const std::string & data, const buffer & signature) const
{
    return eckey_verify(m_eckey, data, signature.code(buffer::code_t::binary));
}

crypto::buffer crypto::ecdsa::shared(const crypto::ecdsa & peer) const
{
    crypto::buffer shared(buffer::code_t::binary);
    eckey_shared(m_eckey, peer.m_eckey, shared);
    return shared;
}


crypto::symmetry_crypto::symmetry_crypto(const void* evp) : m_evp(evp)
{
}

void crypto::symmetry_crypto::dump(std::ostream & ostr) const
{
    ostr << "Block cipher key" << std::endl;
    data_ptr((void*)m_key.data(), m_key.size()).dump(ostr);
    ostr << "Initialization Vector" << std::endl;
    data_ptr((void*)m_iv.data(), m_iv.size()).dump(ostr);

    ostr << "Plain text" << std::endl;
    plain.dump(ostr);
    ostr << "Cipher text" << std::endl;
    cipher.dump(ostr);
    ostr << "Additional Authenticated Data" << std::endl;
    aad.dump(ostr);
    ostr << "Authentication tag" << std::endl;
    tag.dump(ostr);
}

size_t crypto::symmetry_crypto::key_len() const
{
    return size_t(EVP_CIPHER_key_length((const EVP_CIPHER*)m_evp));
}

size_t crypto::symmetry_crypto::iv_len() const
{
    return size_t(EVP_CIPHER_iv_length((const EVP_CIPHER*)m_evp));
}

void crypto::symmetry_crypto::addiv(size_t add)
{
    if (m_iv.empty()) {
        throwx(invalid_argument, "ivsize(%u)", m_iv.size());
    }

    for (size_t i = m_iv.size() - 1; i != std::string::npos && add != 0; i--) {
        add += (uint8_t)m_iv[i];
        m_iv[i] = add % 256;
        add /= 256;
    }
}

bool crypto::symmetry_crypto::encrypt()
{
    return crypto::evp_encrypt((const EVP_CIPHER*)m_evp,
        m_key.data(), m_key.size(), m_iv.data(), m_iv.size(),
        aad.data(), aad.size(), tag.data(), tag.size(),
        plain.data(), plain.size(), cipher.data(), cipher.size());
}

bool crypto::symmetry_crypto::decrypt()
{
    return crypto::evp_decrypt((const EVP_CIPHER*)m_evp,
        m_key.data(), m_key.size(), m_iv.data(), m_iv.size(),
        aad.data(), aad.size(), tag.data(), tag.size(),
        cipher.data(), cipher.size(), plain.data(), plain.size());
}

crypto::chacha20_poly1305::chacha20_poly1305(const std::string & key, const std::string & iv) : symmetry_crypto(EVP_chacha20_poly1305())
{
    (m_key = key).resize(min(key.size(), key_len()));
    (m_iv = iv).resize(min(iv.size(), iv_len()));
}

crypto::aes_256_gcm::aes_256_gcm(const std::string & key, const std::string & iv) : symmetry_crypto(EVP_aes_256_gcm())
{
    (m_key = key).resize(min(key.size(), key_len()));
    (m_iv = iv).resize(min(iv.size(), iv_len()));
}

crypto::aes_128_ecb::aes_128_ecb(const std::string & key) : symmetry_crypto(EVP_aes_128_ecb())
{
    (m_key = key).resize(min(key.size(), key_len()));
}

crypto::des_ede3_ecb::des_ede3_ecb(const std::string & key) : symmetry_crypto(EVP_des_ede3())
{
    (m_key = key).resize(min(key.size(), key_len()));
}


void crypto::dump_bin(std::ostream & ostr, const std::string & data)
{
    crypto::dump_bin(ostr, data.data(), data.size());
}

void crypto::dump_bin(std::ostream & ostr, const void* data, size_t size)
{
    BIO_dump_cb([](const void *data, size_t len, void *u) -> int {
        (*(std::ostream*)u).write((const char*)data, len);
        return (int)len;
    }, &ostr, (const char*)data, (int)size);
    ostr.flush();
}

void crypto::rand_bin(std::string & data)
{
    crypto::rand_bin((void*)data.data(), data.size());
}

void crypto::rand_bin(void* data, size_t size)
{
    RAND_bytes((uint8_t*)data, (int)size);
}

bool crypto::code_b_16(const void* src, size_t size, std::string & dest)
{
    if (src == nullptr || size == 0) {
        throwx(invalid_argument, "src(0x%p):size(%zu)", src, size);
    }

    const uint8_t* psz = (const uint8_t*)src;
    const uint8_t* pend = psz + size;

    dest.clear();

    while (psz != pend) {
        dest += c_b16[*psz / 16];
        dest += c_b16[*psz % 16];

        psz++;
    }
    return !dest.empty();
}

bool crypto::code_16_b(const void* src, size_t size, std::string & dest)
{
    if (src == nullptr || size == 0) {
        throwx(invalid_argument, "src(0x%p):size(%zu)", src, size);
    }

    const uint8_t* psz = (const uint8_t*)src;
    const uint8_t* pend = psz + size;
    size_t length = size;

    dest.clear();

    for (; psz != pend && std::isspace(*psz); psz++, length--);
    while (psz != pend) {
        const char *ch = nullptr;
        if ((length % 2) == 0) {
            ch = strchr(c_b16, *(psz++));
        }
        else {
            ch = c_b16;
            length--;
        }
        if (ch == nullptr) {
            throwx(invalid_argument, "src(%x)", *(--psz));
        }
        const char *cl = strchr(c_b16, *(psz++));
        if (cl == nullptr) {
            throwx(invalid_argument, "src(%x)", *(--psz));
        }
        dest += static_cast<char>((ch - c_b16) * 16 + (cl - c_b16));
    }
    return !dest.empty();
}

bool crypto::code_b_58(const void* src, size_t size, std::string & dest)
{
    if (src == nullptr || size == 0) {
        throwx(invalid_argument, "src(0x%p):size(%zu)", src, size);
    }

    const uint8_t* psz = (const uint8_t*)src;
    const uint8_t* pend = psz + size;
    int32_t zeroes = 0;
    int32_t length = 0;

    for (; psz != pend && *psz == 0; psz++, zeroes++);
    size_t dsize = (size - zeroes) * 138 / 100 + 1;
    std::vector<uint8_t> b58(dsize);

    for (; psz != pend; psz++) {
        int32_t carry = uint8_t(*psz);
        int32_t i = 0;
        for (auto it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); ++it, i++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
        if (carry != 0) {
            throwx(invalid_argument, "carry(%d)", carry);
        }
        length = i;
    }
    auto it = b58.begin() + (dsize - length);
    for (; it != b58.end() && *it == 0; it++);
    dest.reserve(zeroes + (b58.end() - it));
    dest.assign(zeroes, '1');
    for (; it != b58.end(); it++) {
        dest += c_b58[*it];
    }
    return !dest.empty();
}

bool crypto::code_58_b(const void* src, size_t size, std::string & dest)
{
    if (src == nullptr || size == 0) {
        throwx(invalid_argument, "src(0x%p):size(%zu)", src, size);
    }

    const uint8_t* psz = (const uint8_t*)src;
    const uint8_t* pend = psz + size;
    int32_t zeroes = 0;
    int32_t length = 0;
    size_t dsize = size * 733 / 1000 + 1;
    std::vector<uint8_t> b256(dsize);

    for (; psz != pend && std::isspace(*psz); psz++);
    for (; psz != pend && *psz == '1'; psz++, zeroes++);
    for (; psz != pend; psz++) {
        const char* ch = strchr(c_b58, *psz);
        if (ch == nullptr) {
            throwx(invalid_argument, "psz(%c)", *psz);
        }
        int32_t carry = int32_t(ch - c_b58);
        int32_t i = 0;
        for (auto it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        if (carry != 0) {
            throwx(invalid_argument, "carry(%d)", carry);
        }
        length = i;
    }
    auto it = b256.begin() + (dsize - length);
    for (; it != b256.end() && *it == 0; it++);
    dest.reserve(zeroes + (b256.end() - it));
    dest.assign(zeroes, 0x00);
    for (; it != b256.end(); it++) {
        dest += (char)(*it);
    }
    return !dest.empty();
}

bool crypto::code_b_64(const void* src, size_t size, std::string & dest)
{
    if (src == nullptr || size == 0) {
        throwx(invalid_argument, "src(0x%p):size(%zu)", src, size);
    }

    const uint8_t* psz = (const uint8_t*)src;
    const uint8_t* pend = psz + size;
    size_t outpos = 0;
    int32_t bits_collected = 0;
    uint32_t accumulator = 0;

    dest.assign((((size + 2) / 3) * 4), '=');

    for (; psz != pend; psz++) {
        accumulator = (accumulator << 8) | (*psz & 0xffu);
        bits_collected += 8;
        while (bits_collected >= 6) {
            bits_collected -= 6;
            dest[outpos++] = c_b64[(accumulator >> bits_collected) & 0x3fu];
        }
    }
    if (bits_collected > 0) {
        if (bits_collected >= 6) {
            throwx(invalid_argument, "bits_collected(%d)", bits_collected);
        }
        accumulator <<= 6 - bits_collected;
        dest[outpos++] = c_b64[accumulator & 0x3fu];
    }
    return !dest.empty();
}

bool crypto::code_64_b(const void* src, size_t size, std::string & dest)
{
    if (src == nullptr || size == 0) {
        throwx(invalid_argument, "src(0x%p):size(%zu)", src, size);
    }

    const uint8_t* psz = (const uint8_t*)src;
    const uint8_t* pend = psz + size;
    int32_t bits_collected = 0;
    uint32_t accumulator = 0;

    dest.clear();

    for (; psz != pend; psz++) {
        if (std::isspace(*psz) || *psz == '=') {
            continue;
        }
        if (*psz > 127 || r_b64[*psz] > 63) {
            throwx(invalid_argument, "This contains characters not legal in a base64 encoded string.");
        }
        accumulator = (accumulator << 6) | r_b64[*psz];
        bits_collected += 6;
        if (bits_collected >= 8) {
            bits_collected -= 8;
            dest += (char)((accumulator >> bits_collected) & 0xffu);
        }
    }
    return !dest.empty();
}

#define SHA1_DIGEST_LENGTH SHA_DIGEST_LENGTH
#define __HASH__(func, data, size, hash)                                     \
{                                                                            \
    hash.resize(func##_DIGEST_LENGTH);                                       \
    if (func((const uint8_t*)data, size, (uint8_t*)hash.data()) == nullptr) {\
        throwx_crypto(crypto_error, "data(0x%p):size(%zu)", data, size);     \
    }                                                                        \
}

void crypto::md5(const void* data, size_t size, std::string & hash)
{
    __HASH__(MD5, data, size, hash);
}

void crypto::ripemd160(const void * data, size_t size, std::string & hash)
{
    __HASH__(RIPEMD160, data, size, hash);
}

void crypto::sha1(const void* data, size_t size, std::string & hash)
{
    __HASH__(SHA1, data, size, hash);
}

void crypto::sha224(const void* data, size_t size, std::string & hash)
{
    __HASH__(SHA224, data, size, hash);
}

void crypto::sha256(const void* data, size_t size, std::string & hash)
{
    __HASH__(SHA256, data, size, hash);
}

void crypto::sha384(const void* data, size_t size, std::string & hash)
{
    __HASH__(SHA384, data, size, hash);
}

void crypto::sha512(const void* data, size_t size, std::string & hash)
{
    __HASH__(SHA512, data, size, hash);
}

void crypto::eckey_new(void** eckey, const std::string & name)
{
    int32_t nid = OBJ_sn2nid(name.c_str());
    if (nid == NID_undef) {
        throwx_crypto(crypto_error, "name(%s):nid(%d)", name.c_str(), nid);
    }

    *eckey = EC_KEY_new_by_curve_name(nid);
    if (*eckey == nullptr) {
        throwx_crypto(crypto_error, "eckey(0x%p):name(%s)", *eckey, name.c_str());
    }
}

void crypto::eckey_free(void* eckey)
{
    if (eckey != nullptr) {
        EC_KEY_free((EC_KEY*)eckey);
    }
}

void crypto::eckey_get_name(const void* eckey, std::string & name)
{
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    const EC_GROUP* group = EC_KEY_get0_group((const EC_KEY*)eckey);
    if (group == nullptr) {
        throwx_crypto(crypto_error, "eckey(0x%p):group(0x%p)", eckey, group);
    }

    int32_t nid = EC_GROUP_get_curve_name(group);
    if (nid == NID_undef) {
        throwx_crypto(crypto_error, "nid(%d)", nid);
    }

    name = EC_curve_nid2nist(nid);
}

void crypto::eckey_generate(void* eckey)
{
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    if (EC_KEY_generate_key((EC_KEY*)eckey) == 0) {
        throwx_crypto(crypto_error, "eckey(0x%p)", eckey);
    }
}

void crypto::eckey_get_prvkey(const void* eckey, std::string & prvkey)
{
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    const BIGNUM *bnprv = EC_KEY_get0_private_key((const EC_KEY*)eckey);
    if (bnprv == nullptr) {
        throwx_crypto(crypto_error, "eckey(0x%p):bnprv(0x%p)", eckey, bnprv);
    }

    int32_t len = (BN_num_bits(bnprv) + 7) / 8;
    if (len == 0) {
        throwx_crypto(crypto_error, "eckey(0x%p):len(%d)", eckey, len);
    }

    prvkey.resize(len);
    len = BN_bn2bin(bnprv, (uint8_t*)prvkey.data());
    if (len == 0) {
        throwx_crypto(crypto_error, "eckey(0x%p):len(%d):prvkey(0x%p)", eckey, len, prvkey.data());
    }
}

void crypto::eckey_set_prvkey(void* eckey, const std::string & prvkey)
{
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    if (prvkey.empty()) {
        throwx(invalid_argument, "eckey(0x%p):prvsize(%zu)", eckey, prvkey.size());
    }

    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> bnprv(BN_new(), BN_free);
    if (bnprv == nullptr) {
        throwx_crypto(crypto_error, "bnprv(0x%p)", bnprv.get());
    }

    if (BN_bin2bn((const uint8_t*)prvkey.data(), (int)prvkey.size(), bnprv.get()) == nullptr) {
        throwx_crypto(crypto_error, "prvkey(0x%p):size(%zu)", prvkey.data(), prvkey.size());
    }
    if (EC_KEY_set_private_key((EC_KEY*)eckey, bnprv.get()) == 0) {
        throwx_crypto(crypto_error, "eckey(0x%p)", eckey);
    }
}

void crypto::eckey_get_pubkey(const void* eckey, std::string & pubkey)
{
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    int32_t len = i2o_ECPublicKey((const EC_KEY*)eckey, nullptr);
    if (len == 0) {
        throwx_crypto(crypto_error, "eckey(0x%p):len(%d)", eckey, len);
    }

    pubkey.resize(len);
    uint8_t* ppub = (uint8_t*)pubkey.data();
    len = i2o_ECPublicKey((const EC_KEY*)eckey, &ppub);
    if (len == 0) {
        throwx_crypto(crypto_error, "eckey(0x%p):len(%d):pubkey(0x%p)", eckey, len, ppub);
    }

    //
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    const EC_GROUP *group = EC_KEY_get0_group((const EC_KEY*)eckey);
    if (group == nullptr) {
        throwx_crypto(crypto_error, "eckey(0x%p):group(0x%p)", eckey, group);
    }

    const BIGNUM *bnprv = EC_KEY_get0_private_key((const EC_KEY*)eckey);
    if (bnprv == nullptr) {
        throwx_crypto(crypto_error, "eckey(0x%p):bnprv(0x%p)", eckey, bnprv);
    }

    std::unique_ptr<EC_POINT, void(*)(EC_POINT*)> ptpub(EC_POINT_new(group), EC_POINT_free);
    if (ptpub == nullptr) {
        throwx_crypto(crypto_error, "eckey(0x%p):ptpub(0x%p)", eckey, ptpub.get());
    }

    if (EC_POINT_mul(group, ptpub.get(), bnprv, nullptr, nullptr, nullptr) == 0) {
        throwx_crypto(crypto_error, "eckey(0x%p):ptpub(0x%p)", eckey, ptpub.get());
    }
    if (EC_KEY_set_public_key((EC_KEY*)eckey, ptpub.get()) == 0) {
        throwx_crypto(crypto_error, "eckey(0x%p):ptpub(0x%p)", eckey, ptpub.get());
    }

    //std::string pubkey;
    int retlength = 0;
    unsigned char retstr[128] = {0};
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    x = BN_new();
    y = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, ptpub.get(), x, y, NULL)) {
        throwx_crypto(crypto_error, "EC_POINT_get_affine_coordinates_GFp");
    }
    retlength = BN_bn2bin (x, retstr);
    pubkey = std::string((char *)retstr,retlength);
    //<32前面补0
    if(retlength < 32)
    {
        pubkey.insert(pubkey.begin(),32 - retlength, '\x00');
        retlength = 32;
    }
    if(BN_is_odd(y))
    {
        pubkey.insert(pubkey.begin(),'\x03');
    }
    else 
    {
        pubkey.insert(pubkey.begin(),'\x02');
    }
}

void crypto::eckey_set_pubkey(void* eckey, const std::string & pubkey)
{
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    if (pubkey.empty()) {
        throwx(invalid_argument, "eckey(0x%p):pubsize(%zu)", eckey, pubkey.size());
    }

    const uint8_t* ppub = (uint8_t*)pubkey.data();
    if (o2i_ECPublicKey((EC_KEY**)&eckey, &ppub, (long)pubkey.size()) == nullptr) {
        throwx_crypto(crypto_error, "pubkey(0x%p):size(%zu)", ppub, pubkey.size());
    }
}

void crypto::eckey_com_pubkey(void* eckey)
{
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    const EC_GROUP *group = EC_KEY_get0_group((const EC_KEY*)eckey);
    if (group == nullptr) {
        throwx_crypto(crypto_error, "eckey(0x%p):group(0x%p)", eckey, group);
    }

    const BIGNUM *bnprv = EC_KEY_get0_private_key((const EC_KEY*)eckey);
    if (bnprv == nullptr) {
        throwx_crypto(crypto_error, "eckey(0x%p):bnprv(0x%p)", eckey, bnprv);
    }

    std::unique_ptr<EC_POINT, void(*)(EC_POINT*)> ptpub(EC_POINT_new(group), EC_POINT_free);
    if (ptpub == nullptr) {
        throwx_crypto(crypto_error, "eckey(0x%p):ptpub(0x%p)", eckey, ptpub.get());
    }

    if (EC_POINT_mul(group, ptpub.get(), bnprv, nullptr, nullptr, nullptr) == 0) {
        throwx_crypto(crypto_error, "eckey(0x%p):ptpub(0x%p)", eckey, ptpub.get());
    }
    if (EC_KEY_set_public_key((EC_KEY*)eckey, ptpub.get()) == 0) {
        throwx_crypto(crypto_error, "eckey(0x%p):ptpub(0x%p)", eckey, ptpub.get());
    }
}

bool crypto::eckey_check(const void* eckey)
{
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    return EC_KEY_check_key((const EC_KEY*)eckey) == 1;
}

void crypto::eckey_sign(const void* eckey, const std::string & data, std::string & signature)
{
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    if (data.empty()) {
        throwx(invalid_argument, "eckey(0x%p):datasize(%zu)", eckey, data.size());
    }

    std::unique_ptr<ECDSA_SIG, void(*)(ECDSA_SIG*)> sig(ECDSA_do_sign((const uint8_t*)data.data(), (int)data.size(), (EC_KEY*)eckey), ECDSA_SIG_free);
    if (sig == nullptr) {
        throwx_crypto(crypto_error, "sig(0x%p)", sig.get());
    }

    int32_t len = ECDSA_size((const EC_KEY*)eckey);
    if (len == 0) {
        throwx_crypto(crypto_error, "len(%d)", len);
    }

    signature.resize(len);
    uint8_t* psign = (uint8_t*)signature.data();
    len = i2d_ECDSA_SIG(sig.get(), &psign);
    if (len == 0) {
        throwx_crypto(crypto_error, "sig(0x%p):psign(0x%p)", sig.get(), psign);
    }
    signature.resize(len);
}

bool crypto::eckey_verify(const void* eckey, const std::string & data, const std::string & signature)
{
    if (eckey == nullptr) {
        throwx(invalid_argument, "eckey(0x%p)", eckey);
    }

    if (data.empty() || signature.empty()) {
        throwx(invalid_argument, "eckey(0x%p):datasize(%zu):signaturesize(%zu)", eckey, data.size(), signature.size());
    }

    const uint8_t* psign = (uint8_t*)signature.data();
    std::unique_ptr<ECDSA_SIG, void(*)(ECDSA_SIG*)> sig(d2i_ECDSA_SIG(nullptr, &psign, (long)signature.size()), ECDSA_SIG_free);
    if (sig == nullptr) {
        throwx_crypto(crypto_error, "sig(0x%p)", sig.get());
    }

    return ECDSA_do_verify((const uint8_t*)data.data(), (int)data.size(), sig.get(), (EC_KEY*)eckey) == 1;
}

void crypto::eckey_shared(const void* eckey, const void* peer, std::string & shared)
{
    if (eckey == nullptr || peer == nullptr) {
        throwx(invalid_argument, "eckey(0x%p):peer(0x%p)", eckey, peer);
    }

    const EC_GROUP* group = EC_KEY_get0_group((const EC_KEY*)eckey);
    if (group == nullptr) {
        throwx_crypto(crypto_error, "eckey(0x%p):group(0x%p)", eckey, group);
    }

    const EC_POINT* point = EC_KEY_get0_public_key((const EC_KEY*)peer);
    if (point == nullptr) {
        throwx_crypto(crypto_error, "point(0x%p)", point);
    }

    int32_t len = EC_GROUP_get_degree(group);
    if (len == 0) {
        throwx_crypto(crypto_error, "len(%d)", len);
    }

    len = (len + 7) / 8;
    shared.resize(len);

    len = ECDH_compute_key((void*)shared.data(), len, point, (const EC_KEY*)eckey, nullptr);
    if (len == 0) {
        throwx_crypto(crypto_error, "len(%d)", len);
    }

    shared.resize(len);
}

bool crypto::evp_encrypt(const void* evp_cipher,
    const void* key, size_t keysize, const void* iv, size_t ivsize,
    const void* aad, size_t aadsize, void* tag, size_t & tagsize,
    const void* plain, size_t plainsize, void* cipher, size_t & ciphersize)
{
    if (evp_cipher == nullptr || key == nullptr || keysize == 0 /*|| iv == nullptr
        || ivsize == 0*/ || plain == nullptr || plainsize == 0 || cipher == nullptr || ciphersize == 0) {
        throwx(invalid_argument, "evp_cipher(0x%p):key(0x%p):keysize(%zu):iv(0x%p):"
            "ivsize(%zu):plain(0x%p):plainsize(%zu):cipher(0x%p):ciphersize(%zu)",
            evp_cipher, key, keysize, iv, ivsize, plain, plainsize, cipher, ciphersize);
    }

    std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (ctx == nullptr) {
        ctx.reset(EVP_CIPHER_CTX_new());
        if (ctx == nullptr) {
            throwx_crypto(crypto_error, "ctx(0x%p)", ctx.get());
        }
    }
    EVP_CIPHER_CTX_reset(ctx.get());

    if (EVP_EncryptInit_ex(ctx.get(), (EVP_CIPHER*)evp_cipher, nullptr, nullptr, nullptr) != 1) {
        throwx_crypto(crypto_error, "evp_cipher(0x%p)", evp_cipher);
    }
    if (EVP_CIPHER_CTX_set_key_length(ctx.get(), (int)keysize) != 1) {
        throwx_crypto(crypto_error, "keysize(%zu)", keysize);
    }

    uint8_t* _iv = (ivsize != 0) ? (uint8_t*)iv : nullptr;
    if (_iv != nullptr) {
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, (int)ivsize, nullptr) != 1) {
            throwx_crypto(crypto_error, "ivsize(%zu)", ivsize);
        }
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, (uint8_t*)key, _iv) != 1) {
        throwx_crypto(crypto_error, "key(0x%p):iv(0x%p)", key, iv);
    }

    int32_t outlen = 0, templen = 0;
    if (aad != nullptr && aadsize != 0) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, (uint8_t*)aad, (int)aadsize) != 1) {
            throwx_crypto(crypto_error, "aad(0x%p):aadsize(%zu):", aad, aadsize);
        }
    }
    if (EVP_EncryptUpdate(ctx.get(), (uint8_t*)cipher, &outlen, (uint8_t*)plain, (int)plainsize) != 1) {
        throwx_crypto(crypto_error, "plain(0x%p):plainsize(%zu):", plain, plainsize);
    }

    if (EVP_EncryptFinal_ex(ctx.get(), (uint8_t*)cipher + outlen, &templen) != 1) {
        throwx_crypto(crypto_error, "cipher(0x%p):outlen(%d)", cipher, outlen);
    }
    if (ciphersize < size_t(outlen) + size_t(templen)) {
        throwx(overflow_error, "ciphersize(%zu):outlen(%d):templen(%d)", ciphersize, outlen, templen);
    }
    ciphersize = outlen + templen;

    if (tag != nullptr && tagsize != 0) {
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, (int)tagsize, tag) != 1) {
            throwx_crypto(crypto_error, "tag(0x%p):tagsize(%zu):", tag, tagsize);
        }
    }
    return true;
}

bool crypto::evp_decrypt(const void* evp_cipher,
    const void* key, size_t keysize, const void* iv, size_t ivsize,
    const void* aad, size_t aadsize, void* tag, size_t tagsize,
    const void* cipher, size_t ciphersize, void* plain, size_t & plainsize)
{
    if (evp_cipher == nullptr || key == nullptr || keysize == 0 /*|| iv == nullptr
        || ivsize == 0*/ || plain == nullptr || plainsize == 0 || cipher == nullptr || ciphersize == 0) {
        throwx(invalid_argument, "evp_cipher(0x%p):key(0x%p):keysize(%zu):iv(0x%p):"
            "ivsize(%zu):plain(0x%p):plainsize(%zu):cipher(0x%p):ciphersize(%zu)",
            evp_cipher, key, keysize, iv, ivsize, plain, plainsize, cipher, ciphersize);
    }

    std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (ctx == nullptr) {
        ctx.reset(EVP_CIPHER_CTX_new());
        if (ctx == nullptr) {
            throwx_crypto(crypto_error, "ctx(0x%p)", ctx.get());
        }
    }
    EVP_CIPHER_CTX_reset(ctx.get());

    if (EVP_DecryptInit_ex(ctx.get(), (EVP_CIPHER*)evp_cipher, nullptr, nullptr, nullptr) != 1) {
        throwx_crypto(crypto_error, "evp_cipher(0x%p)", evp_cipher);
    }
    if (EVP_CIPHER_CTX_set_key_length(ctx.get(), (int)keysize) != 1) {
        throwx_crypto(crypto_error, "keysize(%zu)", keysize);
    }

    uint8_t* _iv = (ivsize != 0) ? (uint8_t*)iv : nullptr;
    if (_iv != nullptr) {
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, (int)ivsize, nullptr) != 1) {
            throwx_crypto(crypto_error, "ivsize(%zu)", ivsize);
        }
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, (uint8_t*)key, _iv) != 1) {
        throwx_crypto(crypto_error, "key(0x%p):iv(0x%p)", key, iv);
    }

    int32_t outlen = 0, templen = 0;
    if (aad != nullptr && aadsize != 0) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen, (uint8_t*)aad, (int)aadsize) != 1) {
            throwx_crypto(crypto_error, "aad(0x%p):aadsize(%zu):", aad, aadsize);
        }
    }
    if (EVP_DecryptUpdate(ctx.get(), (uint8_t*)plain, &outlen, (uint8_t*)cipher, (int)ciphersize) != 1) {
        throwx_crypto(crypto_error, "cipher(0x%p):ciphersize(%zu):", cipher, ciphersize);
    }

    if (tag != nullptr && tagsize != 0) {
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, (int)tagsize, tag) != 1) {
            throwx_crypto(crypto_error, "tag(0x%p):tagsize(%zu):", tag, tagsize);
        }
    }

    bool ret = EVP_DecryptFinal_ex(ctx.get(), (uint8_t*)plain + outlen, &templen) <= 0;
    if (plainsize < size_t(outlen) + size_t(templen)) {
        throwx(overflow_error, "plainsize(%zu):outlen(%d):templen(%d)", plainsize, outlen, templen);
    }
    plainsize = outlen + templen;
    return ret;
}
