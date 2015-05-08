//
//  RSAHelper.m
//  FinalTestRSA
//
//  Created by YangXu on 14-8-19.
//  Copyright (c) 2014年 huika. All rights reserved.
//

#import "RSAHelper.h"
#import "NSData+MKBase64.h"
#import "DVNCrypto.h"
#import "GDataXMLNode.h"
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

using namespace Diveinedu;
using namespace  std;


static NSString *const kPem = @"hkd.pem";

@implementation RSAHelper

+ (RSAHelper *)sharedInstance
{
    static RSAHelper *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (NSString *)encryString:(NSString *)strToEncry
{
    NSArray *Paths=NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path=[[Paths objectAtIndex:0] stringByAppendingPathComponent:kPem];
    
    string *keyPath = new string([path UTF8String]);
    // 设置公钥
    DVNCrypto crypter;
    crypter.setPublicKey(*keyPath);
    
    // 加密
    string *befor = new string([strToEncry UTF8String]);
    string after = crypter.encrypt(*befor);
    
    NSData *data = [NSData dataWithBytes:after.c_str() length:after.length()];
    
    
    NSString *b64Str = [data base64EncodedString];   // 客户端把这个加密后经过base64转码的数据传到服务器
    
//    NSLog(@"加密前:%s", befor->c_str());
//    NSLog(@"加密后:%@", b64Str);

    return b64Str;
}


- (BOOL)generatePemWithMoAndExXML:(NSString *)xmlStr
{
    GDataXMLDocument *document = [[GDataXMLDocument alloc] initWithXMLString:xmlStr options:0 error:nil];

    GDataXMLElement *rootElement = [document rootElement];
    GDataXMLElement *moElement = [rootElement elementsForName:@"Modulus"][0];
    GDataXMLElement *exElement = [rootElement elementsForName:@"Exponent"][0];

    return [self generatePemWithMo:moElement.stringValue ex:exElement.stringValue];
}

- (BOOL)generatePemWithMo:(NSString *)b64Mo ex:(NSString *)b64Ex
{
    const char * modulus = [b64Mo UTF8String];
    const char * exp = [b64Ex UTF8String];
    
    EVP_PKEY *key = RSA_fromBase64(modulus, exp);
    
    if (key == NULL) {
        NSLog(@"error");
        return NO;
    } else {
        NSArray *Paths=NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *path=[[Paths objectAtIndex:0] stringByAppendingPathComponent:kPem];
        
        NSFileManager *fileManager = [NSFileManager defaultManager];
        
        if ([fileManager fileExistsAtPath:path]) {
            [fileManager removeItemAtPath:path error:nil];
        }
        
        if ([fileManager createFileAtPath:path contents:nil attributes:nil]) {
            FILE* file = fopen([path UTF8String], "w");
            PEM_write_PUBKEY(file, key);
            fflush(file);
            fclose(file);
        } else {
            NSAssert(NO, @"file open failed");
            return NO;
        }
        return YES;
    }
}


unsigned char *base64_decode(const char* base64data, int* len) {
    BIO *b64, *bmem;
    size_t length = strlen(base64data);
    unsigned char *buffer = (unsigned char *)malloc(length);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void*)base64data, length);
    bmem = BIO_push(b64, bmem);
    *len = BIO_read(bmem, buffer, length);
    BIO_free_all(bmem);
    return buffer;
}

BIGNUM* bignum_base64_decode(const char* base64bignum) {
    BIGNUM* bn = NULL;
    int len;
    unsigned char* data = base64_decode(base64bignum, &len);
    if (len) {
        bn = BN_bin2bn(data, len, NULL);
    }
    free(data);
    return bn;
}

EVP_PKEY* RSA_fromBase64(const char* modulus_b64, const char* exp_b64) {
    BIGNUM *n = bignum_base64_decode(modulus_b64);
    BIGNUM *e = bignum_base64_decode(exp_b64);
    
    if (!n) printf("Invalid encoding for modulus\n");
    if (!e) printf("Invalid encoding for public exponent\n");
    
    if (e && n) {
        EVP_PKEY* pRsaKey = EVP_PKEY_new();
        RSA* rsa = RSA_new();
        rsa->e = e;
        rsa->n = n;
        EVP_PKEY_assign_RSA(pRsaKey, rsa);
        return pRsaKey;
    } else {
        if (n) BN_free(n);
        if (e) BN_free(e);
        return NULL;
    }
}

void assert_syntax(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "Description: %s takes a RSA public key modulus and exponent in base64 encoding and produces a public key file in PEM format.\n", argv[0]);
        fprintf(stderr, "syntax: %s <modulus_base64> <exp_base64> <output_file>\n", argv[0]);
        exit(1);
    }
}

@end
