//
//  MyAES.m
//  MyAES
//
//  Created by traximus.td on 14-12-29.
//  Copyright (c) 2014年 ifenglian. All rights reserved.
//

#import "MyAES.h"


//AES
#import "igd_aes.h"
#import <CommonCrypto/CommonCrypto.h>






@implementation MyAES




//how to use
+(void)showHowToUse
{
    NSLog(@"\n\nNSString *secret = @\"guest\";\n\n//测试加密\nNSString *stringNeedEnc = @\"9FC0904E7CE388DE21FA\";\nNSData *dataNeedEnc = [stringNeedEnc dataUsingEncoding:NSUTF8StringEncoding];\nNSString *encedStr = [myAESObj aesEncryptData:dataNeedEnc withSecret:secret needPaddingZero:YES];\n\nNSLog(@\"enc(%%@,%%@)\",stringNeedEnc,secret);\nNSLog(@\"res1:%%@结束标记\",encedStr);\n\n//测试解密\nNSString *hexStr = @\"1C61109AB4FAA76067D532C2E7D911C3DF727E9840C26E954880A90B5519BB60\";\nNSData *dataNeedDec = [myAESObj hexStringToData:hexStr];\nNSData *decedData = [myAESObj aesDencyptData:dataNeedDec withSecret:secret];\nNSString *resultT = [[[NSString alloc]initWithData:decedData encoding:NSUTF8StringEncoding] stringByTrimmingCharactersInSet:[NSCharacterSet controlCharacterSet]];\n\nNSLog(@\"dec(%%@,%%@)\",hexStr,secret);\nNSLog(@\"res2:%%@结束标记\",resultT);");
}


//直接对二进制数据加密 - 加密结果的二进制数据的十六进制字符串
-(NSString *)aesEncryptData:(NSData *)dataT withSecret:(NSString *)secret needPaddingZero:(BOOL)paddingZero
{
    //in
    NSMutableData *inData = [dataT mutableCopy];
    
    //这里添加一位0是为了和c语言端一致
    if (paddingZero) {
        unsigned char iByte;
        memset(&iByte, 0, 1);
        [inData appendBytes:&iByte length:1];
    }
    
    //secret
    //    const unsigned char *secretKey = (const unsigned char *)[secret cStringUsingEncoding:NSASCIIStringEncoding];
    const unsigned char *secretKey = (const unsigned char *)[secret cStringUsingEncoding:NSUTF8StringEncoding];
    
    //out
    int outLength;
    unsigned char *outBuffer = igd_aes_encrypt((const unsigned char *)[inData bytes], (int)[inData length], &outLength, secretKey,(int)[secret length]);
    
    
    NSData *outData = [NSData dataWithBytesNoCopy:outBuffer length:outLength];
    NSString *outString = [[self dataToHexString:outData] uppercaseString];
    
    return outString;
}

//对二进制数据解密
-(NSData *)aesDecyptData:(NSData *)dataT withSecret:(NSString *)secret
{
    //in
    NSData *inData = [dataT mutableCopy];
    NSInteger lengthT = [inData length];
    
    //secret
    //    const unsigned char *secretKey = (const unsigned char *)[secret cStringUsingEncoding:NSASCIIStringEncoding];
    const unsigned char *secretKey = (const unsigned char *)[secret cStringUsingEncoding:NSUTF8StringEncoding];
    
    //out
    unsigned char *outBufferT = igd_aes_decrypt((const unsigned char *)[inData bytes], (int)lengthT, secretKey, (int)[secret length]);
    
    //result
    NSData *outDataT = [[NSData alloc]initWithBytesNoCopy:(void *)outBufferT length:lengthT];
    
    return outDataT;
}

-(NSString *)dataToHexString:(NSData *)dataT;
{
    int index = 0;
    NSString *returnString = [[NSString alloc]init];
    
    while (index<(int)[dataT length])
    {
        unsigned char tempC;
        [dataT getBytes:&tempC range:NSMakeRange(index, 1)];
        returnString = [returnString stringByAppendingFormat:@"%02X",tempC];
        index++;
    }
    
    return returnString;
}

//将hexString还原成data
-(NSData *)hexStringToData:(NSString *)hexString
{
    const char *chars = [hexString UTF8String];
    NSInteger counter = 0;
    NSInteger length = hexString.length;
    
    NSMutableData *dataT = [NSMutableData dataWithCapacity:length/2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (counter < length) {
        byteChars[0] = chars[counter++];
        byteChars[1] = chars[counter++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [dataT appendBytes:&wholeByte length:1];
    }
    
    return dataT;
}


@end
