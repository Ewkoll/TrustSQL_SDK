/*!
 * ╔╦╦═╦═╦╦═╦╦═╦═╦═╦╦╗
 * ║║║═╣═╣║║║╬╬║═╣╬║║║
 * ╚═╩═╩╩╩╩╩═╩═╩═╩═╩═╝
 * date:    4/10/2017
 * Contact: uckzou@tencent.com
 */
#pragma once
#include <string>
#include <sstream>


namespace crypto
{
    typedef void (*hash_f)(const void*, size_t, std::string &);

    class buffer : public std::string
    {
    public:
        enum class code_t
        {
            binary,
            base16,
            base58,
            base64,
        };

    public:
        buffer(code_t type = code_t::binary);
        buffer(const std::string & data, code_t type = code_t::binary);
        buffer(const char* data, size_t size, code_t type = code_t::binary);
        buffer(const buffer & _buffer);
        buffer & operator=(const buffer & _buffer);

        void     dump(std::ostream & ostr) const;

        code_t   type() const;

        buffer & rand(size_t size);
        buffer   code(code_t type) const;
        buffer   hash(hash_f func) const;

    private:
        mutable code_t m_type;
    };

    class data_ptr
    {
    public:
        typedef unsigned char byte_t;

    public:
        data_ptr();
        data_ptr(std::string & data);
        data_ptr(void* data, size_t size);
        data_ptr & operator=(std::string & data);

        void     dump(std::ostream & ostr) const;

        void*  & data();
        size_t & size();
        byte_t & operator[](size_t index);

    private:
        void*  m_data;
        size_t m_size;
    };

    class ecdsa
    {
    public:
        ecdsa(const std::string & name); // name: secp384r1
        ~ecdsa();

        std::string name() const;
        void*  eckey() const;

        void   set_prvkey(const buffer & prvkey);
        buffer get_prvkey() const;
        void   set_pubkey(const buffer & pubkey);
        buffer get_pubkey() const;
        void   com_pubkey();

        void   generate();
        bool   check() const;

        buffer sign(const std::string & data) const;
        bool   verify(const std::string & data, const buffer & signature) const;

        buffer shared(const ecdsa & peer) const;

    private:
        void* m_eckey;
    };

    class symmetry_crypto
    {
    public:
        symmetry_crypto(const void* evp);

        void   dump(std::ostream & ostr) const;

        size_t key_len() const;
        size_t iv_len() const;

        void   addiv(size_t add);

        bool   encrypt();
        bool   decrypt();

        data_ptr plain;     // Plain text
        data_ptr cipher;    // Cipher text
        data_ptr aad;       // Additional Authenticated Data
        data_ptr tag;       // Authentication tag

    protected:
        const void* m_evp;
        std::string m_key;  // Block cipher key
        std::string m_iv;   // Initialization Vector
    };

    /*  ChaCha20/Poly1305 by Google
     *  key: 256 bits
     *  iv:   96 bits
     *  tag:  64 bits
     **/
    class chacha20_poly1305 : public symmetry_crypto
    {
    public:
        chacha20_poly1305(const std::string & key, const std::string & iv);
    };

    /*  Advanced Encryption Standard 256-bit Galois/Counter Mode
     *  key: 256 bits
     *  iv:   96 bits
     *  tag:  64 bits
     **/
    class aes_256_gcm : public symmetry_crypto
    {
    public:
        aes_256_gcm(const std::string & key, const std::string & iv);
    };

    /*  Advanced Encryption Standard 128-bit Electronic Codebook Mode
     *  key: 128 bits
     *  iv:    0 bits
     *  tag:   0 bits
     **/
    class aes_128_ecb : public symmetry_crypto
    {
    public:
        aes_128_ecb(const std::string & key);
    };

    /*  Three key triple DES EDE in Electronic Codebook Mode
     *  key: 192 bits
     *  iv:    0 bits
     *  tag:   0 bits
     **/
    class des_ede3_ecb : public symmetry_crypto
    {
    public:
        des_ede3_ecb(const std::string & key);
    };


    void dump_bin(std::ostream & ostr, const std::string & data);
    void dump_bin(std::ostream & ostr, const void* data, size_t size);
    void rand_bin(std::string & data);
    void rand_bin(void* data, size_t size);

    bool code_b_16(const void* src, size_t size, std::string & dest);
    bool code_16_b(const void* src, size_t size, std::string & dest);
    bool code_b_58(const void* src, size_t size, std::string & dest);
    bool code_58_b(const void* src, size_t size, std::string & dest);
    bool code_b_64(const void* src, size_t size, std::string & dest);
    bool code_64_b(const void* src, size_t size, std::string & dest);

    void md5(const void* data, size_t size, std::string & hash);
    void ripemd160(const void* data, size_t size, std::string & hash);
    void sha1(const void* data, size_t size, std::string & hash);
    void sha224(const void* data, size_t size, std::string & hash);
    void sha256(const void* data, size_t size, std::string & hash);
    void sha384(const void* data, size_t size, std::string & hash);
    void sha512(const void* data, size_t size, std::string & hash);

    void eckey_new(void** eckey, const std::string & name);
    void eckey_free(void* eckey);
    void eckey_get_name(const void* eckey, std::string & name);
    void eckey_generate(void* eckey);
    void eckey_get_prvkey(const void* eckey, std::string & prvkey);
    void eckey_set_prvkey(void* eckey, const std::string & prvkey);
    void eckey_get_pubkey(const void* eckey, std::string & pubkey);
    void eckey_set_pubkey(void* eckey, const std::string & pubkey);
    void eckey_com_pubkey(void* eckey);
    bool eckey_check(const void* eckey);
    void eckey_sign(const void* eckey, const std::string & data, std::string & signature);
    bool eckey_verify(const void* eckey, const std::string & data, const std::string & signature);
    void eckey_shared(const void* eckey, const void* peer, std::string & shared);

    bool evp_encrypt(const void* evp_cipher,
        const void* key, size_t keysize, const void* iv, size_t ivsize,
        const void* aad, size_t aadsize, void* tag, size_t & tagsize,
        const void* plain, size_t plainsize, void* cipher, size_t & ciphersize);
    bool evp_decrypt(const void* evp_cipher,
        const void* key, size_t keysize, const void* iv, size_t ivsize,
        const void* aad, size_t aadsize, void* tag, size_t tagsize,
        const void* cipher, size_t ciphersize, void* plain, size_t & plainsize);

}

