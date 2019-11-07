/*
 * TrustSQL_SDK_V1.1
 **/

#pragma once
#ifdef __cplusplus
extern "C" {
#endif


/*  DIGEST_LENGTH
 *  buffer size, contain the bytes end up with \0
 **/
#define PUBKEY_DIGEST_LENGTH 90     // public key length
#define PRVKEY_DIGEST_LENGTH 45     // private key length
#define ADDR_DIGEST_LENGTH 35       // address length
#define SIGN_DIGEST_LENGTH 98       // signature length
#define KEY_DES3_DIGEST_LENGTH 24   // max size of key for DES3 encrypt
#define KEY_AES128_DIGEST_LENGTH 16 // max size of key for AES128 encrypt
#define TRANSSQL_DIGEST_LENGTH 8192 // max size of trans sql for TrustSQL

/*  GetVersion
 *  return: the sdk verion string
 **/
const char* GetVersionStr();

/*  GetErrorStr
 *  return: the last error string ever happen
 **/
const char* GetErrorStr();

/*  SetCharset
 *  set the local charset for encode string to UTF-8
 *  charset: charset of local system. for simple chinese is: GBK
 *  return: 0 is success, otherwise -1 on error cause
 **/
int SetCharset(const char* charset);

/*  GeneratePairkey
 *  generate a pair of public key and private key
 *  notice: this function will not alloc a buffer for pPrvkey or pPubkey
 *  pPrvkey: param out the buffer of private key, length must be PRVKEY_DIGEST_LENGTH
 *  pPubkey: param out the buffer of public key, length must be PUBKEY_DIGEST_LENGTH
 *  return: 0 is success, otherwise -1 on error cause
 **/
int GeneratePairkey(char* pPrvkey, char* pPubkey);

/*  GeneratePubkeyByPrvkey
 *  convert the private key to public key
 *  notice: this function will not alloc a buffer for pPubkey
 *  pPrvkey: param in the buffer of private key, length must be PRVKEY_DIGEST_LENGTH
 *  pPubkey: param out the buffer of public key, length must be PUBKEY_DIGEST_LENGTH
 *  return: 0 is success, otherwise -1 on error cause
 **/
int GeneratePubkeyByPrvkey(const char* pPrvkey, char* pPubkey);

/*  GenerateAddrByPubkey
 *  calculate the address by public key
 *  notice: this function will not alloc a buffer for pAddr
 *  pPubkey: param in the buffer of public key, length must be PUBKEY_DIGEST_LENGTH
 *  pAddr: param out the buffer of address, length must be ADDR_DIGEST_LENGTH
 *  return: 0 is success, otherwise -1 on error cause
 **/
int GenerateAddrByPubkey(const char* pPubkey, char* pAddr);

/*  GenerateAddrByPrvkey
 *  calculate the address by private key
 *  notice: this function will not alloc a buffer for pAddr
 *  pPrvkey: param in the buffer of private key, length must be PRVKEY_DIGEST_LENGTH
 *  pAddr: param out the buffer of address, length must be ADDR_DIGEST_LENGTH
 *  return: 0 is success, otherwise -1 on error cause
 **/
int GenerateAddrByPrvkey(const char* pPrvkey, char* pAddr);

/*  CheckPairkey
 *  check the pair of public key and private key
 *  pPrvkey: param in the buffer of private key, length must be PRVKEY_DIGEST_LENGTH
 *  pPubkey: param in the buffer of public key, length must be PUBKEY_DIGEST_LENGTH
 *  return: 0 is success and match, 1 is the pair key not match, otherwise -1 on error cause
 **/
int CheckPairkey(const char* pPrvkey, const char* pPubkey);

/*  SignString
 *  sign a string with private key, call 'GetErrorStr' after this function to get the hex string of original buffer for sign
 *  notice: this function will not alloc a buffer for pSign
 *  pPrvkey: param in the buffer of private key, length must be PRVKEY_DIGEST_LENGTH
 *  pStr: param in the buffer of string for sign
 *  nLen: param in the buffer size of string for sign
 *  pSign: param out the buffer of signature, length must be SIGN_DIGEST_LENGTH
 *  return: 0 is success, otherwise -1 on error cause
 **/
int SignString(const char* pPrvkey, const char* pStr, int nLen, char* pSign);

/*  VerifySign
 *  verify a sign with pPubkey key, call 'GetErrorStr' after this function to get the hex string of original buffer for verify
 *  pPubkey: param in the buffer of public key, length must be PUBKEY_DIGEST_LENGTH
 *  pStr: param in the buffer of string for verify
 *  nLen: param in the buffer size of string for verify
 *  pSign: param in the buffer of signature that sign by 'SignString', length must be SIGN_DIGEST_LENGTH
 *  return: 0 is success and verify pass, 1 is verify not pass, otherwise -1 on error cause
 **/
int VerifySign(const char* pPubkey, const char* pStr, int nLen, const char* pSign);

/*  SignRenString 
 *  sign a string with private key, call 'GetErrorStr' after this function to get the hex string of original buffer for sign
 *  notice: this function will not alloc a buffer for pSign
 *  pPrvkey: param in the buffer of private key, length must be PRVKEY_DIGEST_LENGTH
 *  pStr: param in the buffer of string for sign
 *  nLen: param in the buffer size of string for sign
 *  pSign: param out the buffer of signature, length must be SIGN_DIGEST_LENGTH
 *  return: 0 is success, otherwise -1 on error cause
 **/
int SignRenString(const char* pPrvkey, const char* pStr, int nLen, char* pSign);

/*  VerifyRetSign 
 *  verify a sign with pPubkey key, call 'GetErrorStr' after this function to get the hex string of original buffer for verify
 *  pPubkey: param in the buffer of public key, length must be PUBKEY_DIGEST_LENGTH
 *  pStr: param in the buffer of string for verify
 *  nLen: param in the buffer size of string for verify
 *  pSign: param in the buffer of signature that sign by 'SignString', length must be SIGN_DIGEST_LENGTH
 *  return: 0 is success and verify pass, 1 is verify not pass, otherwise -1 on error cause
 **/
int VerifyRetSign(const char* pPubkey, const char* pStr, int nLen, const char* pSign);

/*  EncryptDES3
 *  encrypt a string by Three key triple DES EDE in Electronic Codebook Mode
 *  notice: this function will not alloc a buffer for pCipher
 *  pKey: param in the buffer of des3 key, length must be less than KEY_DES3_DIGEST_LENGTH
 *  pPlain: param in the buffer of plain text
 *  nLen: param in the buffer size of plain text
 *  pCipher: param out the buffer of cipher
 *  nOut: param in and out the buffer size of cipher, on success it will set the cipher length
 *  return: 0 is success, otherwise -1 on error cause
 **/
int EncryptDES3(const char* pKey, const char* pPlain, int nLen, char* pCipher, int* nOut);

/*  DecryptDES3
 *  decrypt a string by Three key triple DES EDE in Electronic Codebook Mode
 *  notice: this function will not alloc a buffer for pPlain
 *  pKey: param in the buffer of des3 key, length must be less than KEY_DES3_DIGEST_LENGTH
 *  pCipher: param in the buffer of cipher
 *  nLen: param in the buffer size of cipher
 *  pPlain: param out the buffer of plain text
 *  nOut: param in and out the buffer size of plain text, on success it will set the plain text length
 *  return: 0 is success, otherwise -1 on error cause
 **/
int DecryptDES3(const char* pKey, const char* pCipher, int nLen, char* pPlain, int* nOut);

/*  EncryptAES128
 *  encrypt a string by Advanced Encryption Standard 128-bit Electronic Codebook Mode
 *  notice: this function will not alloc a buffer for pCipher
 *  pKey: param in the buffer of aes128 key, length must be less than KEY_AES128_DIGEST_LENGTH
 *  pPlain: param in the buffer of plain text
 *  nLen: param in the buffer size of plain text
 *  pCipher: param out the buffer of cipher
 *  nOut: param in and out the buffer size of cipher, on success it will set the cipher length
 *  return: 0 is success, otherwise -1 on error cause
 **/
int EncryptAES128(const char* pKey, const char* pPlain, int nLen, char* pCipher, int* nOut);

/*  DecryptAES128
 *  decrypt a string by Advanced Encryption Standard 128-bit Electronic Codebook Mode
 *  notice: this function will not alloc a buffer for pPlain
 *  pKey: param in the buffer of aes128 key, length must be less than KEY_AES128_DIGEST_LENGTH
 *  pCipher: param in the buffer of cipher
 *  nLen: param in the buffer size of cipher
 *  pPlain: param out the buffer of plain text
 *  nOut: param in and out the buffer size of plain text, on success it will set the plain text length
 *  return: 0 is success, otherwise -1 on error cause
 **/
int DecryptAES128(const char* pKey, const char* pCipher, int nLen, char* pPlain, int* nOut);


#ifdef __cplusplus
}
#endif
