/*!
 * ╔╦╦═╦═╦╦═╦╦═╦═╦═╦╦╗
 * ║║║═╣═╣║║║╬╬║═╣╬║║║
 * ╚═╩═╩╩╩╩╩═╩═╩═╩═╩═╝
 * date:    4/10/2017
 * Contact: uckzou@tencent.com
 */
#include "TrustSQL_SDK.h"
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <time.h>
#if defined _WIN32
#include <windows.h>
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif
#else
#include <sys/time.h>
#endif


long long time_ms()
{
#if defined _WIN32
    FILETIME ft;
    ::GetSystemTimeAsFileTime(&ft);
    long long microsec = 0;
    microsec |= ft.dwHighDateTime;
    microsec <<= 32;
    microsec |= ft.dwLowDateTime;
    microsec /= 10;
    microsec -= DELTA_EPOCH_IN_MICROSECS;
    return microsec / 1000L;
#else
    struct timeval tv;
    ::gettimeofday(&tv, 0);
    return ((long long)(tv.tv_sec) * 1000000L + tv.tv_usec) / 1000L;
#endif
}

class perform
{
public:
    perform() : m_begin(time_ms())
    {
    }
    ~perform()
    {
        long long ended = time_ms();

        snprintf(m_buf, sizeof(m_buf), "begin(%llu):ended(%llu):cost(%llu)", m_begin, ended, ended - m_begin);

        std:: cout << m_buf << std::endl;
    }

private:
    char   m_buf[100];
    long long m_begin;
};

void test_ecdsa()
{
    int ret;
    const char charset[] = "GBK";
    const char src_text[] = "sign_src_text with中文";
    char pubkey[PUBKEY_DIGEST_LENGTH];
    char prvkey[PRVKEY_DIGEST_LENGTH];
    char addr[ADDR_DIGEST_LENGTH];
    char sign[SIGN_DIGEST_LENGTH];

    std::cout << "version: " << GetVersionStr() << std::endl;

    std::cout << "test ecdsa ..." << std::endl;
    do {
        printf("SetCharset: charset(%s)\n", charset);
        if (SetCharset(charset) == 0) {
            printf("ok: charset(%s)\n", charset);
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
            break;
        }

        std::cout << "GeneratePairkey:" << std::endl;
        if (GeneratePairkey(prvkey, pubkey) == 0) {
            printf("ok: prv(%s)\n    pub(%s)\n", prvkey, pubkey);
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
            break;
        }

        std::cout << "GeneratePubkeyByPrvkey:" << std::endl;
        if (GeneratePubkeyByPrvkey(prvkey, pubkey) == 0) {
            printf("ok: prv(%s)\n    pub(%s)\n", prvkey, pubkey);
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
        }

        std::cout << "GenerateAddrByPubkey:" << std::endl;
        if (GenerateAddrByPubkey(pubkey, addr) == 0) {
            printf("ok: pub(%s)\n    addr(%s)\n", pubkey, addr);
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
        }

        std::cout << "GenerateAddrByPrvkey:" << std::endl;
        if (GenerateAddrByPrvkey(prvkey, addr) == 0) {
            printf("ok: prv(%s)\n    addr(%s)\n", prvkey, addr);
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
        }

        std::cout << "CheckPairkey:" << std::endl;
        ret = CheckPairkey(prvkey, pubkey);
        if (ret == 0) {
            printf("ok: prv(%s)\n    pub(%s)\n", prvkey, pubkey);
        }
        else if (ret == 1) {
            printf("unmatch: prv(%s)\n         pub(%s)\n", prvkey, pubkey);
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
            break;
        }

        printf("SignString: sign_src_text(%s)\n", src_text);
        if (SignString(prvkey, src_text, sizeof(src_text) - 1, sign) == 0) {
            printf("ok: prv(%s)\n    sign(%s)\n    %s\n", prvkey, sign, GetErrorStr());
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
            break;
        }

        printf("VerifyString: sign_src_text(%s)\n", src_text);
        ret = VerifySign(pubkey, src_text, sizeof(src_text) - 1, sign);
        if (ret == 0) {
            printf("ok: pub(%s)\n    sign(%s)\n    %s\n", pubkey, sign, GetErrorStr());
        }
        else if (ret == 1) {
            printf("unmatch: pub(%s)\n         sign(%s)\n         %s\n", pubkey, sign, GetErrorStr());
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
        }
    } while (0);
    std::cout << "test ecdsa done" << std::endl;
}

void test_ecdsa_performance()
{
    int loop = 10000;
    const char charset[] = "GBK";
    const char src_text[] = "sign_src_text with中文";
    char pubkey[PUBKEY_DIGEST_LENGTH];
    char prvkey[PRVKEY_DIGEST_LENGTH];
    char sign[SIGN_DIGEST_LENGTH];

    std::cout << "test ecdsa performance..." << std::endl;
    do {
        if (SetCharset(charset) != 0) {
            printf("fail: error(%s)\n", GetErrorStr());
            break;
        }

        {
            perform perf;
            std::cout << "GeneratePairkey: " << loop << " times performance(ms): ";

            for (int i = 0; i < loop; i++) {
                if (GeneratePairkey(prvkey, pubkey) != 0) {
                    printf("fail: error(%s)\n", GetErrorStr());
                    break;
                }
            }
        }

        {
            perform perf;
            std::cout << "SignString: " << loop << " times performance(ms): ";

            for (int i = 0; i < loop; i++) {
                if (SignString(prvkey, src_text, sizeof(src_text) - 1, sign) != 0) {
                    printf("fail: error(%s)\n", GetErrorStr());
                    break;
                }
            }
        }

        {
            perform perf;
            std::cout << "VerifyString: " << loop << " times performance(ms): ";

            for (int i = 0; i < loop; i++) {
                if (VerifySign(pubkey, src_text, sizeof(src_text) - 1, sign) != 0) {
                    printf("fail: error(%s)\n", GetErrorStr());
                    break;
                }
            }
        }
    } while (0);
    std::cout << "test ecdsa performance done" << std::endl;
}

void dump(const char* bin, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x%c", (unsigned char)bin[i], (i != 0 && i % 16 == 0) ? '\n' : ' ');
    }
    printf("\n");
}

void test_crypto()
{
    char pKey[KEY_DES3_DIGEST_LENGTH] = "12345678901234567890123";
    char pKey1[KEY_AES128_DIGEST_LENGTH] = "123456789012345";

    char pPlain[] = "test_crypto1234";
    const int len = sizeof(pPlain) - 1;
    int out;
    char pCipher[len + 16] = { 0 };
    char pPlain1[len + 16] = { 0 };

    std::cout << "test crypto..." << std::endl;
    {
        printf("EncryptDES3:\nPlainText:\n");
        dump(pPlain, len);
        out = len + 16;
        if (EncryptDES3(pKey, pPlain, len, pCipher, &out) == 0) {
            printf("ok: CipherText:\n");
            dump(pCipher, out);
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
        }

        printf("DecryptDES3:\n");
        if (DecryptDES3(pKey, pCipher, out, pPlain1, &out) == 0) {
            printf("ok: Plain1Text:\n");
            dump(pPlain1, out);
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
        }

        if (memcmp(pPlain, pPlain1, len) == 0) {
            printf("pass!\n");
        }
        else {
            printf("not pass!\n");
        }

        printf("EncryptAES128:\nPlainText:\n");
        dump(pPlain, len);
        out = len + 16;
        if (EncryptAES128(pKey1, pPlain, len, pCipher, &out) == 0) {
            printf("ok: CipherText:\n");
            dump(pCipher, out);
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
        }

        printf("DecryptAES128:\n");
        if (DecryptAES128(pKey1, pCipher, out, pPlain1, &out) == 0) {
            printf("ok: Plain1Text:\n");
            dump(pPlain1, out);
        }
        else {
            printf("fail: error(%s)\n", GetErrorStr());
        }

        if (memcmp(pPlain, pPlain1, len) == 0) {
            printf("pass!\n");
        }
        else {
            printf("not pass!\n");
        }
    }
    std::cout << "test crypto done" << std::endl;
}

#if 0
void test_transsql()
{
    char prvkey[PRVKEY_DIGEST_LENGTH] = "FQWD/7uXBnq7JpG9PJGouPLWshPS/czAIdKzw8T8pkQ=";
    const char* Fseqno = "20176813546835121683521";
    const char* Fdst1 = "1KZy9DbqjoZHgjgiABzWMesfSKW4X2iSKo";
    unsigned long long Fdst1_amount = 100;
    const char* Fdst2 = "";
    unsigned long long Fdst2_amount = 0;
    const char* Fassets = "{\"Fassets\":\"test\"}";
    const char* Fattach = "{\"Fattach\":\"test\"}"; 
    const char* Ftime = "2017-4-10 19:33:00";
    char sql[TRANSSQL_DIGEST_LENGTH];

    std::cout << "test generate transsql..." << std::endl;
    printf("prvkey(%s)\n", prvkey);
    printf("Fdst1(%s)\n", Fdst1);
    printf("Fdst1_amount(%llu)\n", Fdst1_amount);
    printf("Fdst2(%s)\n", Fdst2);
    printf("Fdst2_amount(%llu)\n", Fdst2_amount);
    printf("Fassets(%s)\n", Fassets);
    printf("Fattach(%s)\n", Fattach);
    printf("Ftime(%s)\n", Ftime);
    if (GenerateTransSql(Fseqno, prvkey, Fdst1, Fdst1_amount, Fdst2, Fdst2_amount, Fassets, Fattach, Ftime, sql) == 0) {
        printf("ok: sql(%s)\n", sql);
    }
    else {
        printf("fail: error(%s)\n", GetErrorStr());
    }

    std::cout << "test generate transsql done" << std::endl;
}
#endif

void test_generate_sign()
{

    char prvkey[PRVKEY_DIGEST_LENGTH] = "FQWD/7uXBnq7JpG9PJGouPLWshPS/czAIdKzw8T8pkQ=";
    char sign[SIGN_DIGEST_LENGTH] = { 0 };
    const char* info_key = "20176813546835121683521";
    unsigned int info_version = 1;
    unsigned int state = 1;
    const char* content = "{\"content\":\"test\"}";
    const char* notes = "{\"notes\":\"test\"}";
    const char* commit_time = "2017-4-10 19:33:00";

    std::cout << "test generate sign..." << std::endl;
    printf("prvkey(%s)\n", prvkey);
    printf("info_key(%s)\n", info_key);
    printf("info_version(%u)\n", info_version);
    printf("state(%u)\n", state);
    printf("content(%s)\n", content);
    printf("notes(%s)\n", notes);
    printf("commit_time(%s)\n", commit_time);
#if 0
    if (IssSign(info_key, info_version, state, content, notes, commit_time, prvkey, sign) == 0) {
        printf("ok: sign(%s)\n", sign);
    }
    else {
        printf("fail: error(%s)\n", GetErrorStr());
    }
#endif

    std::cout << "test generate sign done" << std::endl;
}

int main(int argc, char * argv[])
{
    test_ecdsa();

    test_ecdsa_performance();

    test_crypto();

//     test_transsql();

//    test_generate_sign();

    return 0;
}
