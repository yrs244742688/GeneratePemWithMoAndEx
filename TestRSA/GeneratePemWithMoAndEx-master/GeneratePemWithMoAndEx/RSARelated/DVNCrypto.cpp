#include "DVNCrypto.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<iostream>
#include<string>
#include<sstream>
#include<vector>


using namespace Diveinedu;
using namespace  std;

Diveinedu::DVNCrypto::DVNCrypto():
    pubkey_rsa(NULL), prikey_rsa(NULL)
{
    this->prikey_cipher="~!@#$%^&*()";

#ifdef OPENSSL_THREADS
    Diveinedu::init_locks();
#endif
}

DVNCrypto::~DVNCrypto()
{
    if(this->pubkey_rsa)
    {
        ::RSA_free(this->pubkey_rsa);
    }
    if(this->prikey_rsa)
    {
        ::RSA_free(this->prikey_rsa);
    }


}

int DVNCrypto::setPublicKey(const string &publickey_path)
{
    if(publickey_path.empty())
        return -1;
    FILE *file;
    RSA *p_rsa;
    OpenSSL_add_all_algorithms();
    if((file=fopen(publickey_path.c_str(),"r"))==NULL){
        perror("open public key file error");
        return -1;
    }
    if((p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL){
//    if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){
        ERR_print_errors_fp(stdout);
        return -1;
    }
    if(this->pubkey_rsa !=NULL)
        RSA_free(this->pubkey_rsa);
    this->pubkey_rsa = p_rsa;
    fclose(file);
    return 0;
}

int DVNCrypto::setPublicKey(const unsigned char *pem_key_buffer, size_t pem_key_buffer_len)
{
    BIO *bufio;
    bufio = BIO_new_mem_buf((void*)pem_key_buffer, pem_key_buffer_len);
    if(bufio ==NULL)
    {
        perror("BIO_new_mem_buf from pem_key_buffer error");
        return -1;
    }
    if(this->pubkey_rsa !=NULL)
        RSA_free(this->pubkey_rsa);
    this->pubkey_rsa = PEM_read_bio_RSAPublicKey(bufio, &this->pubkey_rsa, 0, NULL);
    ::BIO_free(bufio);
    if(this->pubkey_rsa == NULL)
    {
        perror("PEM_read_bio_RSAPublicKey from BIO error");
        return -1;
    }
    return 0;

}

int DVNCrypto::setPrivateKey(const string &privatekey_path, const string& cipher)
{
    if(privatekey_path.empty())
        return -1;

    if(!cipher.empty())
        this->prikey_cipher = cipher;


    RSA *p_rsa = ::RSA_new();
    FILE *file;

    OpenSSL_add_all_algorithms();
    if((file=fopen(privatekey_path.c_str(),"r"))==NULL){
        perror("open private key file error");
        return -1;
    }

//    if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
    if((p_rsa=PEM_read_RSAPrivateKey(file,&p_rsa,NULL,(void*)this->prikey_cipher.c_str()))==NULL){
        ERR_print_errors_fp(stdout);
        perror("PEM_read_RSAPrivateKey from file error");
        return -1;
    }
    if(this->prikey_rsa !=NULL)
        RSA_free(this->prikey_rsa);
    this->prikey_rsa = p_rsa;
    fclose(file);
    return 0;
}

int DVNCrypto::setPrivateKey(const unsigned char *pem_key_buffer, size_t pem_key_buffer_len, const unsigned char *cipher)
{
    BIO *bufio;
    bufio = BIO_new_mem_buf((void*)pem_key_buffer, pem_key_buffer_len);
    if(bufio ==NULL)
    {
        perror("BIO_new_mem_buf from pem_key_buffer error");
        return -1;
    }
    if(cipher!=NULL)
        this->prikey_cipher = (const char*)cipher;

    if(this->prikey_rsa !=NULL)
        RSA_free(this->prikey_rsa);
    this->prikey_rsa = PEM_read_bio_RSAPrivateKey(bufio, &this->prikey_rsa, 0, (void*)this->prikey_cipher.c_str());
    ::BIO_free(bufio);
    if(this->prikey_rsa == NULL){
        perror("PEM_read_bio_RSAPrivateKey from BIO error");
        return -1;
    }

    return 0;
}


int Diveinedu::DVNCrypto::generate_key(const string &publickey_path, const string &privatekey_path, const string &cipher)
{
    (void)cipher;

    if(publickey_path.empty() || privatekey_path.empty() )
    {
        perror("Error, parameters:publickey_path or privatekey_path cann't be  empty string...\n");
        return -1;
    }
    if(!cipher.empty())
        this->prikey_cipher = cipher;

    RSA *rsa=NULL;
    OpenSSL_add_all_algorithms();
    printf("Generating RSA key pair...\n");
    rsa = RSA_generate_key(256, RSA_F4, NULL, NULL);
    if(rsa==NULL)
    {
        perror("Generating RSA key pairerror\n");
        return (-1);
    }
    // 公钥
    BIO *bp = BIO_new(BIO_s_file());
    if(BIO_write_filename(bp, (void *)publickey_path.c_str())<=0)
    {
        perror("Open public key file error\n");
        return (-1);
    }
    if(PEM_write_bio_RSAPublicKey(bp, rsa)!=1)
    {
        perror("Write public key error\n");
        return (-1);
    }
    printf("Save public key file successfully:%s\n",publickey_path.c_str());
    BIO_free_all(bp);


    // 私钥
    bp = BIO_new_file(privatekey_path.c_str(), "w+");
    if(bp==NULL)
    {
        perror("Open private key file error\n");
        return (-1);
    }

    //if(PEM_write_bio_RSAPrivateKey(bp, rsa, EVP_des_ede3_ofb(), (unsigned char*)passwd, strlen(passwd), NULL, NULL)!=1)
    if(PEM_write_bio_RSAPrivateKey(bp, rsa, EVP_des_ede3_ofb(), (unsigned char*)this->prikey_cipher.c_str(), this->prikey_cipher.size(), NULL, NULL)!=1)
    {
        perror("Write private key file error\n");
        return (-1);
    }
    BIO_free_all(bp);
    printf("Save private key file successfully:%s\n",privatekey_path.c_str());
    return 0;
}

string Diveinedu::DVNCrypto::encrypt(const string &plainStr, const string &publickey_path)
{

    if(plainStr.empty()||publickey_path.empty())
    {
        std::cerr << "Error,PlainStr or publickey_path is empty string...."<< std::endl;
        return "";
    }
    if(0!=this->setPublicKey(publickey_path))
    {
        std::cerr << "Error,Failed to read public key from file..."<< std::endl;
        return "";
    }
    return this->encrypt(plainStr);

}

string DVNCrypto::encrypt(const string &plainStr)
{
    string enstr;
    char *encrypted = NULL;
    size_t outlen = 0;
    if(plainStr.empty()||this->pubkey_rsa==NULL)
    {
        return "";
    }
    //blocksize must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes,
    //less than RSA_size(rsa) - 41 for RSA_PKCS1_OAEP_PADDING and exactly RSA_size(rsa) for RSA_NO_PADDING
    size_t blocksize = RSA_size(this->pubkey_rsa) - 11;

    size_t len = plainStr.length();
    size_t i = 0;
    for(;i<len;)
    {
        string enstr_block;
        string tmp=plainStr.substr(i,blocksize<(len-i)?blocksize:(len-i));
        size_t tmlen = tmp.length();
        if(0!=this->dvn_encrypt_block(tmp.c_str(), tmlen, &encrypted,&outlen))
        {
            std::cerr << "Error! Failed to encrypt the plaintext block with pubkey.from byte:"<<i<<" to: "<< tmlen << std::endl;
            return "";
        }
        if(encrypted!=NULL)
        {
            enstr_block = string(encrypted, outlen);
            free(encrypted);
            enstr+=enstr_block;
        }
        i+=tmp.size();
    }
//    return this->bytesToHexString((unsigned char*)enstr.c_str(),enstr.size());
    return enstr;
}

string Diveinedu::DVNCrypto::decrypt(const string &encryptedHexStr, const string &privatekey_path, const string &cipher)
{

    if(encryptedHexStr.empty()||privatekey_path.empty())
    {
        std::cerr << "Error! encryptedHexStr or privatekey_path is empty..."<< std::endl;
        return "";
    }
    if(0!=this->setPrivateKey(privatekey_path, cipher))
    {
        std::cerr << "Error! Failed to read the private key..."<< std::endl;
        return "";
    }

    return this->decrypt(encryptedHexStr);

}

string DVNCrypto::decrypt(const string &encryptedHexStr)
{
    string encryptedStr,destr;
    char * decrypted = NULL;
    size_t outlen = 0;
    encryptedStr = this->hexStringToBytes(encryptedHexStr);

    if(encryptedHexStr.empty()||this->prikey_rsa==NULL)
    {
        std::cerr << "Error! encryptedHexStr is empty or didn't set the private key, before..."<< std::endl;
        return "";
    }
    //blocksize must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes,
    //less than RSA_size(rsa) - 41 for RSA_PKCS1_OAEP_PADDING and exactly RSA_size(rsa) for RSA_NO_PADDING
    size_t blocksize = RSA_size(this->prikey_rsa);;

    size_t len = encryptedStr.length();
    size_t i = 0;
    for(;i<len;)
    {
        string destr_block;
        string tmp=encryptedStr.substr(i,blocksize<(len-i)?blocksize:(len-i));
        size_t tmplen = tmp.length();
        if(0!=this->dvn_decrypt_block(tmp.c_str(),tmplen, &decrypted, &outlen))
        {
            std::cerr << "Error! Failed to decrypt the encrytedStr with the specified private key. from byte: "<<i<<" to: "<<i+tmplen<< std::endl;
            return "";
        }
        if(decrypted!=NULL)
        {
            destr_block = string(decrypted);
            free(decrypted);
            destr+=destr_block;
        }
        i+=tmp.size();
    }
    return destr;
}


int DVNCrypto::dvn_encrypt_block(const char *plain_str_block, size_t inlen, char **encrypted_block, size_t *outlen)
{
    if(plain_str_block ==NULL || encrypted_block==NULL||outlen==NULL||this->pubkey_rsa==NULL)
    {
        return -1;
    }
    OpenSSL_add_all_algorithms();
    unsigned char *p_en=NULL;
    size_t rsa_len = RSA_size(this->pubkey_rsa);
    if(inlen > rsa_len -11) //RSA_PKCS1_PADDING
    {//flen must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes,
     //less than RSA_size(rsa) - 41 for RSA_PKCS1_OAEP_PADDING and exactly RSA_size(rsa) for RSA_NO_PADDING .
        return -1;
    }
    p_en=(unsigned char *)malloc(rsa_len+1);
    if(p_en==NULL) return -1;
    memset(p_en,0,rsa_len+1);
    int encrypted_size=0;
    if( (encrypted_size=RSA_public_encrypt(inlen, (unsigned char *)plain_str_block, (unsigned char*)p_en,
                                           this->pubkey_rsa, RSA_PKCS1_PADDING /*RSA_NO_PADDING*/)) < 0){
        ERR_print_errors_fp(stdout);
        return -1;
    }
    *encrypted_block = (char*)p_en;
    *outlen = encrypted_size;//;
    return 0;
}




int DVNCrypto::dvn_decrypt_block(const char *encrypted_str_block, size_t inlen, char **decrypted_block, size_t *outlen)
{
    if(encrypted_str_block ==NULL || decrypted_block == NULL||outlen==NULL||this->prikey_rsa==NULL)
    {
        return -1;
    }
    unsigned char *p_de=NULL;
    OpenSSL_add_all_algorithms();

    size_t rsa_len = RSA_size(this->prikey_rsa);
    if(inlen > rsa_len )
    {
        return -1;
    }
    p_de=(unsigned char *)malloc(rsa_len+1);
//    p_de= (unsigned char *)malloc(BN_num_bytes(this->prikey_rsa->n));
    if(p_de==NULL) return -1;
    memset(p_de,0,rsa_len+1);
    int decrypted_size = 0;
    if((decrypted_size = RSA_private_decrypt(rsa_len/*inlen*/, (unsigned char *)encrypted_str_block,
                                     (unsigned char*)p_de, this->prikey_rsa, RSA_PKCS1_PADDING /*RSA_NO_PADDING*/))<0){
        ERR_print_errors_fp(stdout);
        return -1;
    }
    *decrypted_block = (char*)p_de;
    *outlen = decrypted_size;//rsa_len+1;
    return 0;
}

inline char Diveinedu::DVNCrypto::intToHexChar(int x)
{
    static const char HEX[16] = {
        '0', '1', '2', '3',
        '4', '5', '6', '7',
        '8', '9', 'A', 'B',
        'C', 'D', 'E', 'F'
    };
    return HEX[x];
}

inline int Diveinedu::DVNCrypto::hexCharToInt(char hex)
{
    hex = toupper(hex);
    if (isdigit(hex))
        return (hex - '0');
    if (isalpha(hex))
        return (hex - 'A' + 10);
    return 0;
}

string Diveinedu::DVNCrypto::bytesToHexString(const byte *in, size_t size, bool space)
{
    string str;
    for (size_t i = 0; i < size; ++i) {
        int t = in[i];
        int a = t / 16;
        int b = t % 16;
        str.append(1, intToHexChar(a));
        str.append(1, intToHexChar(b));
        if (space && (i != size - 1))
            str.append(1, ' ');
    }
    return str;
}

string Diveinedu::DVNCrypto::hexStringToBytes(const string &str)
{
    string out;
 #if 0

#else
    string trimed=this->trim(str);
    int len = trimed.length()/2 + 1;
    out.resize(trimed.length()/2);
    int i = 0;
    byte *p;
    for(i=0, p = (byte *) trimed.c_str(); i<len; i++) {
        out[i] = (hexCharToInt(*p) << 4) | hexCharToInt(*(p+1));
        p += 2;
    }
#endif
    return out;
}

string Diveinedu::DVNCrypto::trim(const string &str, string::size_type pos)
{
    string trimStr = str;
    static const string delim = " \t"; //删除空格或者tab字符
    pos = trimStr.find_first_of(delim, pos);
    if (pos == string::npos)
        return trimStr;
    return trim(trimStr.erase(pos, 1));
}

