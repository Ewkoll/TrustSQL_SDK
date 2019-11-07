/*!
 * ╔╦╦═╦═╦╦═╦╦═╦═╦═╦╦╗
 * ║║║═╣═╣║║║╬╬║═╣╬║║║
 * ╚═╩═╩╩╩╩╩═╩═╩═╩═╩═╝
 * date:    4/10/2017
 * Contact: uckzou@tencent.com
 */
#include "TrustSQL_SDK.h"
#include "json/json.h"
#include "crypto.h"
#include "strconv.h"
#include <map>
#include <string.h>
#include <stdexcept>

thread_local char s_error[4096];

extern "C" const char* GetVersionStr()
{
    const static char* s_version = "TrustSQL_SDK_V1.1";
    return s_version;
}

extern "C" const char* GetErrorStr()
{
    return s_error;
}

extern "C" int SetCharset(const char * charset)
{
    s_error[0] = 0;
    try
    {
        util::set_charset(charset);
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}

int GeneratePairkey(char* pPrvkey, char* pPubkey)
{
    s_error[0] = 0;
    try
    {
        memset(pPrvkey, 0, PRVKEY_DIGEST_LENGTH);
        memset(pPubkey, 0, PUBKEY_DIGEST_LENGTH);

        crypto::ecdsa ec("secp256k1");
        ec.generate();
        strncpy(pPrvkey, ec.get_prvkey().code(crypto::buffer::code_t::base64).c_str(), PRVKEY_DIGEST_LENGTH);
        strncpy(pPubkey, ec.get_pubkey().code(crypto::buffer::code_t::base64).c_str(), PUBKEY_DIGEST_LENGTH);
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}

extern "C" int GeneratePubkeyByPrvkey(const char* pPrvkey, char* pPubkey)
{
    s_error[0] = 0;
    try
    {
        memset(pPubkey, 0, PUBKEY_DIGEST_LENGTH);

        crypto::ecdsa ec("secp256k1");
        ec.set_prvkey(crypto::buffer(pPrvkey, crypto::buffer::code_t::base64));
        ec.com_pubkey();
        strncpy(pPubkey, ec.get_pubkey().code(crypto::buffer::code_t::base64).c_str(), PUBKEY_DIGEST_LENGTH);
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}

extern "C" int GenerateAddrByPubkey(const char* pPubkey, char* pAddr)
{
    s_error[0] = 0;
    try
    {
        memset(pAddr, 0, ADDR_DIGEST_LENGTH);

#if 1
        crypto::buffer step1 = crypto::buffer(pPubkey, crypto::buffer::code_t::base64).code(crypto::buffer::code_t::binary).hash(crypto::sha256).hash(crypto::ripemd160);
        crypto::buffer step2 = crypto::buffer(step1.insert(0, std::string(1, '\x00'))).hash(crypto::sha256).hash(crypto::sha256);

        fprintf(stdout, "step1=%s\n", crypto::buffer(step1, crypto::buffer::code_t::binary).code(crypto::buffer::code_t::base16).c_str());
        fprintf(stdout, "step2=%s\n", crypto::buffer(step2, crypto::buffer::code_t::binary).code(crypto::buffer::code_t::base16).c_str());

        crypto::buffer addr;
        addr.resize(step1.size() + 4);
        memcpy(&addr[0], step1.data(), step1.size());
        memcpy(&addr[step1.size()], step2.data(), 4);
#else
        crypto::buffer step1 = crypto::buffer(pPubkey, crypto::buffer::code_t::base64).code(crypto::buffer::code_t::binary).hash(crypto::sha256).hash(crypto::ripemd160);
        crypto::buffer step2 = step1.hash(crypto::sha256).hash(crypto::sha256);

        crypto::buffer addr;
        addr.resize(1 + step1.size() + 4);
        addr[0] = 0;
        memcpy(&addr[1], step1.data(), step1.size());
        memcpy(&addr[1 + step1.size()], step2.data(), 4);
#endif
        strncpy(pAddr, addr.code(crypto::buffer::code_t::base58).c_str(), ADDR_DIGEST_LENGTH);
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}

extern "C" int GenerateAddrByPrvkey(const char* pPrvkey, char* pAddr)
{
    int result = 0;
    s_error[0] = 0;
    try
    {
        memset(pAddr, 0, ADDR_DIGEST_LENGTH);

        crypto::ecdsa ec("secp256k1");
        ec.set_prvkey(crypto::buffer(pPrvkey, crypto::buffer::code_t::base64));
        ec.com_pubkey();
        result = GenerateAddrByPubkey(ec.get_pubkey().code(crypto::buffer::code_t::base64).c_str(), pAddr);
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        result = -1;
    }

    return result;
}

extern "C" int CheckPairkey(const char* pPrvkey, const char* pPubkey)
{
    int result = 0;
    s_error[0] = 0;
    try
    {
        crypto::ecdsa ec("secp256k1");
        ec.set_prvkey(crypto::buffer(pPrvkey, crypto::buffer::code_t::base64));
        ec.set_pubkey(crypto::buffer(pPubkey, crypto::buffer::code_t::base64));
        result = ec.check() ? 0 : 1;
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        result = -1;
    }

    return result;
}

extern "C" int SignString(const char* pPrvkey, const char* pStr, int nLen, char* pSign)
{
    s_error[0] = 0;
    try
    {
        memset(pSign, 0, SIGN_DIGEST_LENGTH);

        crypto::ecdsa ec("secp256k1");
        ec.set_prvkey(crypto::buffer(pPrvkey, crypto::buffer::code_t::base64));
        strncpy(pSign, ec.sign(crypto::buffer(util::strconv(util::strconv::code_t::mbs, util::strconv::code_t::utf8).code(pStr, nLen)).hash(crypto::sha256)).code(crypto::buffer::code_t::base64).c_str(), SIGN_DIGEST_LENGTH);
        //strncpy(pSign, ec.sign(crypto::buffer(pStr, nLen, crypto::buffer::code_t::base16).code(crypto::buffer::code_t::binary)).code(crypto::buffer::code_t::base64).c_str(), SIGN_DIGEST_LENGTH);

        snprintf(s_error, sizeof(s_error), "sign_src_text_hex(%s)", crypto::buffer(util::strconv(util::strconv::code_t::mbs, util::strconv::code_t::utf8).code(pStr, nLen)).code(crypto::buffer::code_t::base16).c_str());
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}

extern "C" int VerifySign(const char* pPubkey, const char* pStr, int nLen, const char* pSign)
{
    int result = 0;
    s_error[0] = 0;
    try
    {
        crypto::ecdsa ec("secp256k1");
        ec.set_pubkey(crypto::buffer(pPubkey, crypto::buffer::code_t::base64));
        result = ec.verify(crypto::buffer(util::strconv(util::strconv::code_t::mbs, util::strconv::code_t::utf8).code(pStr, nLen)).hash(crypto::sha256), crypto::buffer(pSign, crypto::buffer::code_t::base64)) ? 0 : 1;

        snprintf(s_error, sizeof(s_error), "sign_src_text_hex(%s)", crypto::buffer(util::strconv(util::strconv::code_t::mbs, util::strconv::code_t::utf8).code(pStr, nLen)).code(crypto::buffer::code_t::base16).c_str());
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        result = -1;
    }

    return result;
}

extern "C" int GenerateTransSql(const char * Fseqno, const char * pSrcPrvkey, const char * Fdst1, unsigned long long Fdst1_amount, const char * Fdst2, unsigned long long Fdst2_amount, const char * Fassets, const char * Fattach, const char * Ftime, char* pSql)
{
    char Fsrc[ADDR_DIGEST_LENGTH] = { 0 };
    char Fpubkey[PUBKEY_DIGEST_LENGTH] = { 0 };
    char Fsign[SIGN_DIGEST_LENGTH] = { 0 };

    s_error[0] = 0;
    try
    {
        if (GenerateAddrByPrvkey(pSrcPrvkey, Fsrc) != 0)
        {
            return -1;
        }

        if (GeneratePubkeyByPrvkey(pSrcPrvkey, Fpubkey) != 0)
        {
            return -1;
        }

        std::map<std::string, std::string> mpsig;
        mpsig["Fseqno"] = Fseqno;
        mpsig["Fsrc"] = Fsrc;
        mpsig["Fdst1"] = Fdst1;
        mpsig["Fdst1_amount"] = std::to_string(Fdst1_amount);
        mpsig["Fdst2"] = Fdst2;
        mpsig["Fdst2_amount"] = std::to_string(Fdst2_amount);
        mpsig["Fassets"] = CJson(Fassets).Marshal('&');
        mpsig["Fattach"] = CJson(Fattach).Marshal('&');
        mpsig["Ftime"] = Ftime;
        mpsig["Fpubkey"] = Fpubkey;

        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it)
        {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
        }

        if (SignString(pSrcPrvkey, sigss.data(), sigss.size(), Fsign) != 0)
        {
            return -1;
        }

        memset(pSql, 0, TRANSSQL_DIGEST_LENGTH);
        snprintf(pSql, TRANSSQL_DIGEST_LENGTH,
            "insert into t_transaction "
            "(Fseqno,Fsrc,Fdst1,Fdst1_amount,Fdst2,Fdst2_amount,Ftime,Fpubkey,Fsign,Fassets,Fattach) "
            "values ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s');",
            mpsig["Fseqno"].c_str(),
            mpsig["Fsrc"].c_str(),
            mpsig["Fdst1"].c_str(),
            mpsig["Fdst1_amount"].c_str(),
            mpsig["Fdst2"].c_str(),
            mpsig["Fdst2_amount"].c_str(),
            mpsig["Ftime"].c_str(),
            mpsig["Fpubkey"].c_str(),
            Fsign,
            Fassets,
            Fattach);
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}

extern "C" int SignRenString(const char* pPrvkey, const char* pStr, int nLen, char* pSign)
{
    s_error[0] = 0;
    try
    {
        memset(pSign, 0, SIGN_DIGEST_LENGTH);

        crypto::ecdsa ec("secp256k1");
        ec.set_prvkey(crypto::buffer(pPrvkey, crypto::buffer::code_t::base64));
        strncpy(pSign, ec.sign(crypto::buffer(pStr, nLen, crypto::buffer::code_t::base16).code(crypto::buffer::code_t::binary)).code(crypto::buffer::code_t::base64).c_str(), SIGN_DIGEST_LENGTH);

        snprintf(s_error, sizeof(s_error), "sign_src_text_hex(%s)", crypto::buffer(util::strconv(util::strconv::code_t::mbs, util::strconv::code_t::utf8).code(pStr, nLen)).code(crypto::buffer::code_t::base16).c_str());
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}

extern "C" int VerifyRetSign(const char* pPubkey, const char* pStr, int nLen, const char* pSign)
{
    int result = 0;
    s_error[0] = 0;
    try
    {
        crypto::ecdsa ec("secp256k1");
        ec.set_pubkey(crypto::buffer(pPubkey, crypto::buffer::code_t::base64));
        result = ec.verify((crypto::buffer(pStr, nLen, crypto::buffer::code_t::base16).code(crypto::buffer::code_t::binary)).code(crypto::buffer::code_t::base64), crypto::buffer(pSign, crypto::buffer::code_t::base64)) ? 0 : 1;

        snprintf(s_error, sizeof(s_error), "sign_src_text_hex(%s)", crypto::buffer(util::strconv(util::strconv::code_t::mbs, util::strconv::code_t::utf8).code(pStr, nLen)).code(crypto::buffer::code_t::base16).c_str());
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        result = -1;
    }

    return result;
}


extern "C" int EncryptDES3(const char * pKey, const char * pPlain, int nLen, char * pCipher, int* nOut)
{
    s_error[0] = 0;
    try
    {
        crypto::des_ede3_ecb e(std::string(pKey, KEY_DES3_DIGEST_LENGTH));
        e.plain = crypto::data_ptr((void*)pPlain, nLen);
        e.cipher = crypto::data_ptr((void*)pCipher, *nOut);
        e.encrypt();
        *nOut = (int)e.cipher.size();
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}

extern "C" int DecryptDES3(const char * pKey, const char * pCipher, int nLen, char * pPlain, int* nOut)
{
    s_error[0] = 0;
    try
    {
        crypto::des_ede3_ecb e(std::string(pKey, KEY_DES3_DIGEST_LENGTH));
        e.plain = crypto::data_ptr((void*)pPlain, *nOut);
        e.cipher = crypto::data_ptr((void*)pCipher, nLen);
        e.decrypt();
        *nOut = (int)e.plain.size();
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}

extern "C" int EncryptAES128(const char * pKey, const char * pPlain, int nLen, char * pCipher, int* nOut)
{
    s_error[0] = 0;
    try
    {
        crypto::aes_128_ecb e(std::string(pKey, KEY_AES128_DIGEST_LENGTH));
        e.plain = crypto::data_ptr((void*)pPlain, nLen);
        e.cipher = crypto::data_ptr((void*)pCipher, *nOut);
        e.encrypt();
        *nOut = (int)e.cipher.size();
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}

extern "C" int DecryptAES128(const char * pKey, const char * pCipher, int nLen, char * pPlain, int* nOut)
{
    s_error[0] = 0;
    try
    {
        crypto::aes_128_ecb e(std::string(pKey, KEY_AES128_DIGEST_LENGTH));
        e.plain = crypto::data_ptr((void*)pPlain, *nOut);
        e.cipher = crypto::data_ptr((void*)pCipher, nLen);
        e.decrypt();
        *nOut = (int)e.plain.size();
    }
    catch (const std::exception & e)
    {
        strncpy(s_error, e.what(), sizeof(s_error));
        return -1;
    }

    return 0;
}



