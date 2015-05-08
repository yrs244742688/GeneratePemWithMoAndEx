#ifndef DVNCRYPTO_H
#define DVNCRYPTO_H
#include <iostream>
#include <string>
#include <sstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <assert.h>

typedef unsigned char byte;
typedef unsigned long ulong;



namespace Diveinedu
{

using namespace  std;

class DVNCrypto
{
public:
    DVNCrypto();
    ~DVNCrypto();
    
    //设置公钥，从文件读取公钥
    /*
    *   1. publickey_path  公钥文件路径
    *   成功返回 0
    *   失败返回非0
    */
    int setPublicKey(const string& publickey_path);
    //设置公钥，从内存地址读取公钥
    /*
    *   1. pem_key_buffer       存放公钥的内存起始地址
    *   2. pem_key_buffer_len   缓冲区长度
    *   成功返回 0
    *   失败返回非0
    */
    int setPublicKey(const unsigned char* pem_key_buffer, size_t pem_key_buffer_len = -1);
    //设置私钥，从文件读取私钥
    /*
    *   1. privatekey_path  私钥文件路径
    *   2. cipher           私钥的加密密码
    *   成功返回 0
    *   失败返回非0
    */
    int setPrivateKey(const string& privatekey_path, const string& cipher = "");
    //设置私钥，从内存地址读取私钥
    /*
    *   1. pem_key_buffer       存放私钥的内存起始地址
    *   2. pem_key_buffer_len   缓冲区长度
    *   3. cipher               私钥的加密密码
    *   成功返回 0
    *   失败返回非0
    */
    int setPrivateKey(const unsigned char* pem_key_buffer, size_t pem_key_buffer_len = -1, const unsigned char* cipher=NULL);
    //生成密钥对
    /*
    *   1. publickey_path  公钥文件输出路径
    *   2. privatekey_path 私钥文件输出路径
    *   3. cipher          私钥文件加密密码
    *   成功返回 0
    *   失败返回非0
    */
    int generate_key(const string& publickey_path, const string& privatekey_path, const string& cipher = "");

    //用提供的公钥文件对明文进行加密，
    /*
    *   1. plainStr         需要加密的明文字符串
    *   2. publickey_path   加密明文的公钥文件路径
    *   成功返回加密密文的16进制字符串
    *   失败返回空串
    */
    string encrypt(const string &plainStr, const string& publickey_path);

    //用已经设置好的公钥对明文进行加密，
    /*
    *   1. plainStr         需要加密的明文字符串
    *   成功返回加密密文的16进制字符串
    *   失败返回空串
    */
    string encrypt(const string &plainStr);
    //用提供的私钥文件对密文进行解密，
    /*
    *   1. encryptedHexStr  需要解密的密文16进制字符串
    *   2. privatekey_path   用来解密密文的私钥文件路径
    *   成功返回解密后的明文字符串
    *   失败返回空串
    */
    string decrypt(const string &encryptedHexStr, const string& privatekey_path, const string& cipher = "");

    //用已经设置好的私钥对密文进行解密，
    /*
    *   1. encryptedHexStr  需要解密的密文16进制字符串
    *   成功返回解密后的明文字符串
    *   失败返回空串
    */
    string decrypt(const string &encryptedHexStr);
private:

    int dvn_encrypt_block(const char *plain_str_block, size_t inlen, char **encrypted_block, size_t *outlen);     //用设置好的公钥加密

    int dvn_decrypt_block(const char *encrypted_str_block, size_t inlen, char **decrypted_block, size_t *outlen);

    char intToHexChar(int x);
    int hexCharToInt(char hex);
    string bytesToHexString(const byte *in, size_t size, bool space=false);
    string hexStringToBytes(const string &str);
    string trim(const string &str, string::size_type pos = 0);


private:
    RSA *pubkey_rsa;
    RSA *prikey_rsa;
    string prikey_cipher;
};








/*  openssl thread locks functions */

#ifdef OPENSSL_THREADS
/* we have this global to let the callback get easy access to it */
static pthread_mutex_t *lockarray=NULL;


#include <openssl/crypto.h>
static void lock_callback(int mode, int type, const char *file, int line)
{
  (void)file;
  (void)line;
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lockarray[type]));
  }
  else {
    pthread_mutex_unlock(&(lockarray[type]));
  }
}

static unsigned long thread_id(void)
{
  unsigned long ret;

  ret=(unsigned long)pthread_self();
  return(ret);
}

static void init_locks(void)
{
    if(lockarray!=NULL)
        return;

    int i;
    lockarray=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
                                                sizeof(pthread_mutex_t));
    assert(lockarray);

    for (i=0; i<CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&(lockarray[i]),NULL);
    }

    CRYPTO_set_id_callback((unsigned long (*)())thread_id);
    CRYPTO_set_locking_callback(lock_callback);
}

static void kill_locks(void)
{
    if(lockarray==NULL)
        return;

    int i;
    CRYPTO_set_locking_callback(NULL);
    for (i=0; i<CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&(lockarray[i]));

    OPENSSL_free(lockarray);
    lockarray=NULL;
}
#endif // OPENSSL_THREADS





}//end namespace




#endif // DVNCRYPTO_H
