//
//  RSAHelper.h
//  FinalTestRSA
//
//  Created by YangXu on 14-8-19.
//  Copyright (c) 2014年 huika. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSAHelper : NSObject

+ (RSAHelper *)sharedInstance;

/**
 *  根据模和指数生成pem文件
 *  @param b64Mo base64编码模数
 *  @param b64Ex 6ase64编码指数
 */
- (BOOL)generatePemWithMo:(NSString *)b64Mo ex:(NSString *)b64Ex;

/**
 *  根据模数和指数XML串生成pem文件
 *  @param xmlStr 模数和指数XML串
 */
- (BOOL)generatePemWithMoAndExXML:(NSString *)xmlStr;

/**
 *  字符串RSA加密
 *  @param string 需要加密的字符串
 *  @return 加密后的字符串
 */
- (NSString *)encryString:(NSString *)strToEncry;

@end
