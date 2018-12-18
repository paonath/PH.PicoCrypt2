# PH.PicoCrypt2 - [![NuGet Badge](https://buildstats.info/nuget/PH.PicoCrypt2)](https://www.nuget.org/packages/PH.PicoCrypt2/)
netstandard utility for simple crypt/decrypt 

The AesCrypt service class work using Rijndael.

The package is available on  [nuget](https://www.nuget.org/packages/PH.PicoCrypt2) 

## Features

- text encryption
- text decryption
- calculate hash
- generate random strings

## Code Examples

**EncryptUtf8(string plainText, string password)**
```c#
IPicoCrypt a = new AesCrypt();
var cypherText = a.EncryptUtf8("a string","a password value");
var text2 = a.EncryptUtf8("a string","a password value","a password value");

//cypherText == text2 
```


**EncryptUtf8(string plainText, string password, string salt)**
```c#
IPicoCrypt a = new AesCrypt();
var cypherText = a.EncryptUtf8("a string","a password value","a password salt");
```


**DecryptUtf8(string plainText, string password, string salt)**
```c#
var s = "zQIcqlKjN9euhZdHbNo6aQ==";
var p = "a password";

IPicoCrypt a = new AesCrypt();

var plainText = a.DecryptUtf8(s, p);
//plainText: "a string"
```
