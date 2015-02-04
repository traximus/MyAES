MyAES
=================

a static library project for AES encrypt & decrypt, work with binary data;


----

##how to use
see `+(void)showHowToUse`


```
//对二进制数据加密 -  结果为已加密后的二进制数据的十六进制字符串
    paddingZero - 在进行字符串加密的时候，是否添加二进制数据0，
                  目的在于帮助c语言端判断是否到达字符串结尾；
                  若服务器端没有进行此处理，可以传NO;

-(NSString *)aesEncryptData:(NSData *)dataT withSecret:(NSString *)secret needPaddingZero:(BOOL)paddingZero;


//对二进制数据进行解密 - 结果为已解密的二进制数据
-(NSData *)aesDecyptData:(NSData *)dataT withSecret:(NSString *)secret;

```

----

