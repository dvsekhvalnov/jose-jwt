# Ultimate Javascript Object Signing and Encryption (JOSE) and JSON Web Token (JWT) Implementation for .NET and .NET Core

Minimallistic zero-dependency library for generating, decoding and encryption [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10). Supports full suite
of [JSON Web Algorithms](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31) as of July 4, 2014 version. JSON parsing agnostic, can plug any desired JSON processing library.
Extensively tested for compatibility with [jose.4.j](https://bitbucket.org/b_c/jose4j/wiki/Home), [Nimbus-JOSE-JWT](https://bitbucket.org/nimbusds/nimbus-jose-jwt/wiki/Home) and [json-jwt](https://github.com/nov/json-jwt) libraries.

## FIPS compliance ##
Library is fully FIPS compliant since v2.1

## Which version?
- v2.1 and above added extra features support for .NET461+ and coming with 3 version of binaries (`NET4`, `NET461` and `netstandard1.4`).

- v2.0 and above is .NET Core compatible and aimed to support both .NET framework (`NET40`) and .NET Core (`netstandard1.4`) runtimes. This is the version you should prefer unless you have really strong reason to stay with v1.9.

- v1.9 is built against .NET framework only and should be compatible with `NET40` and above. The version is not actively maintained anymore except critical bug fixes.

- WinRT compatible version (Windows 8.1 and Windows Phone 8.1) is avaliable as standalone project here: [jose-rt](https://github.com/dvsekhvalnov/jose-rt).

- PCLCrypto based experimental project living up here: [jose-pcl](https://github.com/dvsekhvalnov/jose-pcl).


## Foreword
Originally forked from https://github.com/johnsheehan/jwt . Almost re-written from scratch to support JWT encryption capabilities and unified interface for encoding/decoding/encryption
and other features.
Moved to separate project in February 2014.

AES Key Wrap implementation ideas and test data from http://www.cryptofreak.org/projects/rfc3394/ by Jay Miller

## Supported JWA algorithms

### CLR

**Signing**
- HMAC signatures with HS256, HS384 and HS512.
- ECDSA signatures with ES256, ES384 and ES512.
- RSASSA-PKCS1-V1_5 signatures with RS256, RS384 and RS512.
- RSASSA-PSS signatures (probabilistic signature scheme with appendix) with PS256, PS384 and PS512.
- NONE (unprotected) plain text algorithm without integrity protection

**Encryption**
- RSAES OAEP 256 (using SHA-256 and MGF1 with SHA-256) encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- RSAES OAEP (using SHA-1 and MGF1 with SHA-1) encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- RSAES-PKCS1-V1_5 encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- Direct symmetric key encryption with pre-shared key A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM and A256GCM
- A128KW, A192KW, A256KW encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- A128GCMKW, A192GCMKW, A256GCMKW encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- ECDH-ES<sup>\*</sup> with A128CBC-HS256, A128GCM, A192GCM, A256GCM
- ECDH-ES+A128KW<sup>\*</sup>, ECDH-ES+A192KW<sup>\*</sup>, ECDH-ES+A256KW<sup>\*</sup> with A128CBC-HS256, A128GCM, A192GCM, A256GCM
- PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM

**Compression**

- DEFLATE compression

### CORECLR

**Signing**
- HMAC signatures with HS256, HS384 and HS512.
- ECDSA signatures with ES256, ES384 and ES512.
- RSASSA-PKCS1-V1_5 signatures with RS256, RS384 and RS512.
- NONE (unprotected) plain text algorithm without integrity protection

**Encryption**
- RSAES OAEP 256 (using SHA-256 and MGF1 with SHA-256) encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- RSAES OAEP (using SHA-1 and MGF1 with SHA-1) encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- RSAES-PKCS1-V1_5 encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- Direct symmetric key encryption with pre-shared key A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM and A256GCM
- A128KW, A192KW, A256KW encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- A128GCMKW, A192GCMKW, A256GCMKW encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM

**Compression**

- DEFLATE compression

##### Notes:
* Types returned by crytographic methods MAY be different on Windows and Linux. e.g. GetRSAPrivateKey() on X509Certificate2 on Windows returns RsaCng and OpenSslRsa on *nix.
* It appears that Microsoft CNG implementation of BCryptSecretAgreement/NCryptSecretAgreement contains a bug for calculating Elliptic Curve Diffie-Hellman secret agreement
on keys higher than 256 bit (P-384 and P-521 NIST curves correspondingly). At least produced secret agreements do not match any other implementation in different languages.
Technically it is possible to use ECDH-ES or ECDH-ES+AES Key Wrap family with A192CBC-HS384 and A256CBC-HS512 but most likely produced JWT tokens will not be compatible with other platforms and therefore can't be decoded correctly.

## Installation
### NuGet
https://www.nuget.org/packages/jose-jwt/

`Install-Package jose-jwt`

### Manual
Grab source and compile yourself:
  1. `dotnet restore`
  1. `dotnet pack -c Release`

## Usage
### Creating Plaintext (unprotected) Tokens

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

string token = Jose.JWT.Encode(payload, null, JwsAlgorithm.none);
```

### Creating signed Tokens
#### HS-\* family
HS256, HS384, HS512 signatures require `byte[]` array key of corresponding length

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string token=Jose.JWT.Encode(payload, secretKey, JwsAlgorithm.HS256);
```
#### RS-\* and PS-\* family
**NET40-NET45**:

RS256, RS384, RS512 and PS256, PS384, PS512 signatures require `RSACryptoServiceProvider` (usually private) key of corresponding length. CSP need to be forced to use Microsoft Enhanced RSA and AES Cryptographic Provider.
Which usually can be done be re-importing RSAParameters. See http://clrsecurity.codeplex.com/discussions/243156 for details.

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var privateKey=new X509Certificate2("my-key.p12", "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;

string token=Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.RS256);
```

**NETCORE**:
RS256, RS384, RS512 and PS256, PS384, PS512 signatures require `RSA` (usually private) key of corresponding length.

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var privateKey=new X509Certificate2("my-key.p12", "password").GetRSAPrivateKey();

string token=Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.RS256);
```
**NET461**:
Accepts `RSACryptoServiceProvider`, `RSA` or `CngKey` types of keys. 


#### ES-\*  family
**NET40-NET45**:
ES256, ES384, ES512 ECDSA signatures requires `CngKey` (usually private) elliptic curve key of corresponding length. Normally existing `CngKey` loaded via `CngKey.Open(..)` method from Key Storage Provider.
But if you want to use raw key material (x,y) and d, jose-jwt provides convenient helper `EccKey.New(x,y,d)`.

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

var privateKey=EccKey.New(x, y, d);

string token=Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.ES256);
```

**NETCORE**:
ES256, ES384, ES512 ECDSA signatures can accept either `CngKey`(see above) or `ECDsa` (usually private) elliptic curve key of corresponding length.

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var privateKey=new X509Certificate2("ecc-key.p12", "password").GetECDsaPrivateKey();

string token=Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.ES256);
```
**NET461**:
Accepts `CngKey` and `ECDsa` types of keys. 


### Creating encrypted Tokens
#### RSA-\* key management family of algorithms

**NET40-NET45**:

RSA-OAEP-256, RSA-OAEP and RSA1_5 key management requires `RSACryptoServiceProvider` (usually public) key of corresponding length.

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var publicKey=new X509Certificate2("my-key.p12", "password").PublicKey.Key as RSACryptoServiceProvider;

string token = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM);
```

**NETCORE:**
RSA-OAEP-256, RSA-OAEP and RSA1_5 key management requires `RSA` (usually public) key of corresponding length.

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var publicKey=new X509Certificate2("my-key.p12", "password").GetRSAPublicKey();

string token = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM);
```

**NET461**:
Accepts `RSACryptoServiceProvider`, `RSA` or `CngKey` types of keys. 


#### DIR direct pre-shared symmetric key family of algorithms
Direct key management with pre-shared symmetric keys requires `byte[]` array key of corresponding length

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string token = Jose.JWT.Encode(payload, secretKey, JweAlgorithm.DIR, JweEncryption.A128CBC_HS256);
```

#### AES Key Wrap key management family of algorithms
AES128KW, AES192KW and AES256KW key management requires `byte[]` array key of corresponding length

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string token = Jose.JWT.Encode(payload, secretKey, JweAlgorithm.A256KW, JweEncryption.A256CBC_HS512);
```

#### AES GCM Key Wrap key management family of algorithms
AES128GCMKW, AES192GCMKW and AES256GCMKW key management requires `byte[]` array key of corresponding length

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string token = Jose.JWT.Encode(payload, secretKey, JweAlgorithm.A256GCMKW, JweEncryption.A256CBC_HS512);
```

#### ECDH-ES and ECDH-ES with AES Key Wrap key management family of algorithms
ECDH-ES and ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW key management requires `CngKey` (usually public) elliptic curve key of corresponding length. Normally existing `CngKey` loaded via `CngKey.Open(..)` method from Key Storage Provider.
But if you want to use raw key material (x,y) and d, jose-jwt provides convenient helper `EccKey.New(x,y,usage:CngKeyUsages.KeyAgreement)`.

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };

var publicKey=EccKey.New(x, y, usage:CngKeyUsages.KeyAgreement);

string token = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.ECDH_ES, JweEncryption.A256GCM);
```

#### PBES2 using HMAC SHA with AES Key Wrap key management family of algorithms
PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW key management requires `string` passphrase from which key will be derived

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};  	

string token = Jose.JWT.Encode(payload, "top secret", JweAlgorithm.A256KW, JweEncryption.A256CBC_HS512);
```

#### Optional compressing payload before encrypting
Optional DEFLATE compression is supported

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var publicKey=new X509Certificate2("my-key.p12", "password").PublicKey.Key as RSACryptoServiceProvider;

string token = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.RSA1_5, JweEncryption.A128CBC_HS256, JweCompression.DEF);
```

### Verifying and Decoding Tokens
Decoding json web tokens is fully symmetric to creating signed or encrypted tokens:

**HS256, HS384, HS512** signatures, **A128KW, A192KW, A256KW**, **A128GCMKW, A192GCMKW, A256GCMKW** and **DIR** key management algorithms expects `byte[]` array key

```C#
string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg";

byte[] secretKey=new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string json = Jose.JWT.Decode(token, secretKey);
```

**RS256, RS384, RS512**, **PS256, PS384, PS512** signatures and **RSA-OAEP-256**, **RSA-OAEP, RSA1_5** key management algorithms expects

**NET40-NET45**: `RSACryptoServiceProvider` as a key, public/private is asymmetric to encoding:

```C#
string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";

var privateKey=new X509Certificate2("my-key.p12", "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;

string json = Jose.JWT.Decode(token,privateKey);
```

**NETCORE**: `RSA` as a key, public/private is asymmetric to encoding:
```C#
string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";

var privateKey=new X509Certificate2("my-key.p12", "password").GetRSAPrivateKey();

string json = Jose.JWT.Decode(token,privateKey);
```
**NET461**: `RSACryptoServiceProvider`, `RSA` or `CngKey` types of keys, public/private is asymmetric to encoding.



**ES256, ES284, ES512** signatures expects 

**NET40-NET45**: `CngKey` as a key, public/private is asymmetric to encoding. If `EccKey.New(...)` wrapper is used, make
sure correct `usage:` value is set. Should be `CngKeyUsages.Signing` for ES-* signatures (default value, can be ommited).

```C#
string token = "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA";

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };

var publicKey=EccKey.New(x, y);

string json = Jose.JWT.Decode(token,publicKey);
```

**NETCORE**: can accept either `CngKey` (see above) or `ECDsa` as a key, public/private is asymmetric to encoding.

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var publicKey=new X509Certificate2("ecc-key.p12", "password").GetECDsaPublicKey();

string token=Jose.JWT.Encode(payload, publicKey, JwsAlgorithm.ES256);
```

**NET461**: accepts `CngKey` and `ECDsa` types of keys, public/private is asymmetric to encoding.


**ECDH-ES** and **ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW** key management algorithms expects `CngKey` as a key, public/private is asymmetric to encoding. If `EccKey.New(...)` wrapper is used, make
sure correct `usage:` value is set. Should be `CngKeyUsages.KeyAgreement` for ECDH-ES.

```C#
string token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJPbDdqSWk4SDFpRTFrcnZRTmFQeGp5LXEtY3pQME40RVdPM1I3NTg0aEdVIiwieSI6Ik1kU2V1OVNudWtwOWxLZGU5clVuYmp4a3ozbV9kTWpqQXc5NFd3Q0xaa3MiLCJjcnYiOiJQLTI1NiJ9fQ..E4XwpWZ2kO-Vg0xb.lP5LWPlabtmzS-m2EPGhlPGgllLNhI5OF2nAbbV9tVvtCckKpt358IQNRk-W8-JNL9SsLdWmVUMplrw-GO-KA2qwxEeh_8-muYCw3qfdhVVhLnOF-kL4mW9a00Xls_6nIZponGrqpHCwRQM5aSr365kqTNpfOnXgJTKG2459nqv8n4oSfmwV2iRUBlXEgTO-1Tvrq9doDwZCCHj__JKvbuPfyRBp5T7d-QJio0XRF1TO4QY36GtKMXWR264lS7g-T1xxtA.vFevA9zsyOnNA5RZanKqHA";

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

var privateKey=EccKey.New(x, y, d, CngKeyUsages.KeyAgreement);

string json = Jose.JWT.Decode(token, privateKey);

```


**PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW** key management algorithms expects `string` passpharase as a key

```C#
string token = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo4MTkyLCJwMnMiOiJiMFlFVmxMemtaNW9UUjBMIn0.dhPAhJ9kmaEbP-02VtEoPOF2QSEYM5085V6zYt1U1qIlVNRcHTGDgQ.4QAAq0dVQT41dQKDG7dhRA.H9MgJmesbU1ow6GCa0lEMwv8A_sHvgaWKkaMcdoj_z6O8LaMSgquxA-G85R_5hEILnHUnFllNJ48oJY7VmAJw0BQW73dMnn58u161S6Ftq7Mjxxq7bcksWvFTVtG5RsqqYSol5BZz5xm8Fcj-y5BMYMvrsCyQhYdeGEHkAvwzRdvZ8pGMsU2XPzl6GqxGjjuRh2vApAeNrj6MwKuD-k6AR0MH46EiNkVCmMkd2w8CNAXjJe9z97zky93xbxlOLozaC3NBRO2Q4bmdGdRg5y4Ew.xNqRi0ouQd7uo5UrPraedg";

string json = Jose.JWT.Decode(token, "top secret");
```

## Additional utilities

### Adding extra headers
jose-jwt allows to pass extra headers when encoding token to overide deafault values<sup>\*</sup>. `extraHeaders:` named param can be used, it accepts `IDictionary<string, object>` type.
jose-jwt is NOT allow to override `alg` and `enc` headers .

```C#
var payload = new Dictionary<string, object>()
{
     { "sub", "mr.x@contoso.com" },
     { "exp", 1300819380 }
};

var headers = new Dictionary<string, object>()
{
     { "typ", "JWT" },
     { "cty", "JWT" },
     { "keyid", "111-222-333"}
};

var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string token = Jose.JWT.Encode(payload, secretKey, JweAlgorithm.A256GCMKW, JweEncryption.A256CBC_HS512, extraHeaders: headers);
```

```C#
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var headers = new Dictionary<string, object>()
{
     { "typ", "JWT" },
     { "cty", "JWT" },
     { "keyid", "111-222-333"}
};

var privateKey=new X509Certificate2("my-key.p12", "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;

string token=Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.RS256, extraHeaders: headers);
```

\* For backwards compatibility signing uses pre-configured `typ: 'JWT'` header by default.

### Two-phase validation
In some cases validation (decoding) key can be unknown prior to examining token content. For instance one can use different keys per token issuer or rely on headers information to determine which key to use,
do logging or other things.

jose-jwt provides helper methods to examine token content without performing actual integrity validation or decryption.

`IDictionary<string, object> Jose.JWT.Headers(String token)` to return header information as dictionary and `T Jose.JWT.Headers<T>(string token)` to return headers information as
unmarshalled type.

`string Jose.JWT.Payload(string token)` to return unparsed payload and `T Jose.JWT.Payload<T>(string token)` to return unmarshalled payload type. Those 2 methods works only with
signed tokens and will throw `JoseException` when applied on encrypted token.

**Security warning: please note, you should NOT rely on infromation extracted by given helpers without performing token validation as second step.**

Below are couple examples on how two-phase validation can be implemented with jose-jwt:
```C#
//step 1a: get headers info
var headers = Jose.JWT.Headers(token);

//step 1b: lookup validation key based on header info
var key = FindKey(headers["keyid"]);

//step 2: perform actual token validation
var payload = Jose.JWT.Decode(token, key);
```

```C#
//step 1a: get payload as custom JwtToken object
var jwt = Jose.JWT.Payload<JwtToken>(token);

//step 1b: lookup validation key based on issuer
var key = FindKeyByIssuer(jwt.Iss);

//step 2: perform actual token validation
var payload = Jose.JWT.Decode<JwtToken>(token, key);
```

```C#
// Validate token with a public RSA key published by the IDP as a list of JSON Web Keys (JWK)
// step 0: you've read the keys from the jwks_uri URL found in http://<IDP authority URL>/.well-known/openid-configuration endpoint
Dictionary<string, ServiceStack.Text.JsonObject> keys = GetKeysFromIdp();

// step 1a: get headers info
var headers = Jose.JWT.Headers(token);

// step 1b: lookup validation key based on header info
var jwk = keys[headers["keyid"]];

// step 1c: load the JWK data into an RSA key
RSACryptoServiceProvider key = new RSACryptoServiceProvider();
key.ImportParameters(new RSAParameters
{
    Modulus = Base64Url.Decode(jwk["n"]),
    Exponent = Base64Url.Decode(jwk["e"])
});

// step 2: perform actual token validation
var paylod = Jose.JWT.Decode(token, key);
```

### Strict validation
It is possible to use strict validation before decoding a token. This means that you will specify which algorithm and possibly encryption type you are expecting to receive in the header. If the received header doesn't match with the types that you have specified an exception will be thrown and the parsing will be stopped.

Example of how to strictly validate an encrypted token:
```C#
string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg";

byte[] secretKey = new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };

string json = Jose.JWT.Decode(token, secretKey, JweAlgorithm.DIR, JweEncryption.A256GCM);
```

Example of how to strictly validate a signed token:
```C#
string token = "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA";

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };

var publicKey = EccKey.New(x, y);

string json = Jose.JWT.Decode(token, publicKey, JwsAlgorithm.ES256);
```

### Working with binary payload

It is possible to encode and decode JOSE objects that have a payload consisting of arbitrary binary data. The methods that work with a binary payload have the Bytes suffix in the name to distinguish them in cases of potential ambiguity, e.g. `EncodeBytes()`.

Example of working with signed binary payloads in JOSE objects:
```C#
var payload = new byte[] { 1, 2, 3, 0, 255 };
var signingKey = Convert.FromBase64String("WbQs8GowdRX1zYCFi3/VuQ==");

// Encoding a token with a binary payload.
var token = Jose.JWT.EncodeBytes(payload, signingKey, Jose.JwsAlgorithm.HS256);

// Reading the binary payload from a token (with signature verification).
var decoded = Jose.JWT.DecodeBytes(token, signingKey);

// Reading the binary payload from a token (without signature verification).
decoded = Jose.JWT.PayloadBytes(token);
```

### Parsing and mapping json to object model directly
jose-jwt library is agnostic about object model used to represent json payload as well as underlying framework used to serialize/parse json objects. Library provides convinient generic methods to work directly with your object model:

```C#
MyDomainObject obj=Jose.JWT.Decode<MyDomainObject>(token,secretKey); //will invoke configured IJsonMapper to perform parsing/mapping of content to MyDomainObject

string data=Jose.JWT.Encode(obj,secrectKey,JwsAlgorithm.HS256); //for object argument configured IJsonMapper will be invoked to serialize object to json string before encoding
```

## Settings
As of v2.3.0 settings can be configured either globally or on a per-call basis using a `JwtSettings` object.  The `JWT.DefaultSettings` object can be modified to change global settings, or a `JwtSettings` instance can be passed to any public method on `JWT` to override the global settings for particular method call.
It is possible to provide custom implementations of:
- specific signing `JwtSettings.RegisterJws(alg, impl)` 
- encryption,      `JwtSettings.RegisterJwe(alg, impl)`
- key management   `JwtSettings.RegisterJwa(alg, impl)`
- or compression   `JwtSettings.RegisterCompression(alg, impl)`
- json mapper      `JwtSettings.RegisterMapper(mapper)`

as well as specify aliases when decoding tokens from 3rd party libraries that do not comply exactly to spec:
- signing `JwtSettings.RegisterJwsAlias(header, alg)`
- encryption `JwtSettings.RegisterJweAlias(header, alg)`
- key management `JwtSettings.RegisterJwaAlias(header, alg)`
- compression `JwtSettings.RegisterCompressionAlias(header, alg)`

### Example of JWTSettings

```C#
// global setting
Jose.JWT.DefaultSettings.JsonMapper = new Jose.NewtonsoftMapper();


Jose.JWTSettings settings = new Jose.JwtSettings();
settings.JsonMapper = new Jose.JSSerializerMapper(); 

// override global settings for this call
Jose.JWT.Decode(token, secretKey, settings: settings);

//or simply
Jose.JWT.Decode(token, secretKey, settings: new JwtSettings().RegisterMapper(new Jose.JSSerializerMapper()));
```

### Customizing json <-> object parsing & mapping
The library provides simple `Jose.IJsonMapper` interface to plug any json processing library or customize default behavior. The only requirement for mapping implementations
is ability to correctly serialize/parse `IDictionary<string,object>` type.

The default supplied `Jose.IJsonMapper` implementation is based on `System.Web.Script.Serialization.JavaScriptSerializer`.

#### Example of Newtonsoft.Json mapper

```C#
public class NewtonsoftMapper : IJsonMapper
{
    public string Serialize(object obj)
    {
         var settings = new JsonSerializerSettings
         {
         	ContractResolver = new DictionaryKeysResolver(),
         	NullValueHandling = NullValueHandling.Ignore,                                                              
         };

        return JsonConvert.SerializeObject(obj, Formatting.Indented, settings);		
    }

    public T Parse<T>(string json)
    {
        var settings = new JsonSerializerSettings
        {
            ContractResolver = new DictionaryKeysResolver(),
            NullValueHandling = NullValueHandling.Ignore,
        };

        return JsonConvert.DeserializeObject<T>(json, settings);
    }
}

Jose.JWT.DefaultSettings.JsonMapper = new NewtonsoftMapper();
```

#### Example of ServiceStack mapper
```C#
public class ServiceStackMapper : IJsonMapper
{
    public string Serialize(object obj)
    {
        return ServiceStack.Text.JsonSerializer.SerializeToString(obj);
    }

    public T Parse<T>(string json)
    {
        return ServiceStack.Text.JsonSerializer.DeserializeFromString<T>(json);
    }
}

Jose.JWT.DefaultSettings.JsonMapper = new ServiceStackMapper();
```

### Customizing algorithm implementations
The default implementations of any of the signing, encryption, key management, or compression algorithms can be overridden.

#### Example of custom algorithm implementation
```C#
public class CustomKeyManagement : IKeyManagement
{
    public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
    {
        // implement custom key unwrapping (e.g. using Amazon KMS for instance)
    }

    public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
    {
        // implement custom key wrapping (e.g. using Amazon KMS for instance)
    }
}

...

// set default RSA-OAEP key management to use custom implementation
Jose.JWT.DefaultSettings.RegisterJwa(JweAlgorithm.RSA_OAEP, new CustomKeyManagement());
```

### Providing aliases
It is possible to add any number of aliases when decoding for signing, encryption, key management, or compression algorithms. For example if you are
dealing with tokens produced from 3rd party library which you have no control over and by mistake it is using `RSA_OAEP_256` header value instead
of `RSA-OAEP-256` it is possible to register alias:

```C#
   Jose.JWT.Decode(token, key, settings: new JwtSettings().RegisterJwaAlias("RSA_OAEP_256", JweAlgorithm.RSA_OAEP_256));
```

Multiple calls can be chained for more convinience:

```C#
Jose.JWT.Decode(token, secretKey, settings: new JwtSettings()
						.RegisterMapper(customMapper)
						.RegisterJws(JwsAlgorithm.RS256, amazonKmsImpl)
						.RegisterJws(JwsAlgorithm.RS384, amazonKmsImpl)
						.RegisterJws(JwsAlgorithm.RS512, amazonKmsImpl)
						.RegisterJwa(JweAlgorithm.RSA_OAEP_256, hsmImpl)						
						.RegisterJwe(JweEncryption.A128GCM, linuxGcmImpl)						
						.RegisterJwaAlias("RSA_OAEP_256", JweAlgorithm.RSA_OAEP_256)
						.RegisterCompression(JweCompression.DEF, hardwareAcceleratedDeflate)
);
```


## More examples
Checkout UnitTests\TestSuite.cs for more examples.

## Dealing with keys
Below is collection of links and approaches to nail down some common questions around key management:

### RSACryptoServiceProvider
When you dealing with `RSACryptoServiceProvider` you can face `Invalid algorithm specified` exception while performing signing or encryption operations. The reason usually is that underneath `RSACryptoServiceProvider` is not using Microsoft Enhanced RSA and AES Cryptographic Provider. There are several ways to fix that:

1. re-import RSAParameters:

  ```C#
  public static RSACryptoServiceProvider FixCSP(RSACryptoServiceProvider key)
  {
      var privKey = key.PrivateKey;

      RSACryptoServiceProvider newKey = new RSACryptoServiceProvider();
      newKey.ImportParameters(privKey.ExportParameters(true));

      return newKey;
  }
  ```

  The limitation of this approach is that private key should be marked exportable. It is not recommended for production environments but can be handy for testing.

1. Enforce correct CSP:
  ```C#
  public static RSACryptoServiceProvider FixCSP(RSACryptoServiceProvider key)
  {
      var privKey = key.PrivateKey;
      var enhCsp = new RSACryptoServiceProvider().CspKeyContainerInfo;
      var cspParams = new CspParameters(enhCsp.ProviderType, enhCsp.ProviderName, privKey.CspKeyContainerInfo.KeyContainerName);

      return new RSACryptoServiceProvider(cspParams);
  }
  ```

  For more details see: http://stackoverflow.com/questions/7444586/how-can-i-sign-a-file-using-rsa-and-sha256-with-net

1. Actually use certificate which supports SHA-2, see http://hintdesk.com/c-how-to-fix-invalid-algorithm-specified-when-signing-with-sha256/ for details how to create one.

### If you have only RSA private key
E.g. if you don't have .p12 file where certificate is combined with private key that can be loaded via `X509Certificate2` but rather have
only private key:
 ```
 -----BEGIN RSA PRIVATE KEY-----
 ............................
 -----END RSA PRIVATE KEY-----
 ```

Then take a look at: http://www.donaldsbaconbytes.com/2016/08/create-jwt-with-a-private-rsa-key/

## Strong-Named assembly
`jose-jwt` is not providing standalone strong-named assembly as of now. If you need one in your project, please take a look at https://github.com/dvsekhvalnov/jose-jwt/issues/5

Usually people have success with https://github.com/brutaldev/StrongNameSigner

## ASP.NET Core MVC JWT Authentication

### Securing Controllers Using AuthorizeAttribute

ASP.NET Team provides [Microsoft.AspNetCore.Authentication.JwtBearer](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.JwtBearer/) that can be used to authorize web service routes using JWT Tokens created using JOSE-JWT that are passed via `Authorize: Bearer` HTTP header.

In `startup.cs`, you can add JWT Authorization middleware by using `UseJwtBearerAuthentication` extension method against the `IApplicationBuilder app` parameter in `void Configure` method.

Below is the example for setting up the middleware using HS-\* signed token:

```csharp
using System;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Builder;

// The key length needs to be of sufficient length, or otherwise an error will occur.
var tokenSecretKey = Encoding.UTF8.GetBytes(Configuration["TokenSecretKey"]);

var tokenValidationParameters = new TokenValidationParameters
{
    // Token signature will be verified using a private key.
    ValidateIssuerSigningKey = true,
    RequireSignedTokens = true,
    IssuerSigningKey = new SymmetricSecurityKey(tokenSecretKey),

    // Token will only be valid if contains "accelist.com" for "iss" claim.
    ValidateIssuer = true,
    ValidIssuer = "accelist.com",

    // Token will only be valid if contains "accelist.com" for "aud" claim.
    ValidateAudience = true,
    ValidAudience = "accelist.com",

    // Token will only be valid if not expired yet, with 5 minutes clock skew.
    ValidateLifetime = true,
    RequireExpirationTime = true,
    ClockSkew = new TimeSpan(0, 5, 0),

    ValidateActor = false,
};
            
app.UseJwtBearerAuthentication(new JwtBearerOptions
{
    AutomaticAuthenticate = true,
    TokenValidationParameters = tokenValidationParameters,
});
```

After that, your Controllers or Actions can be secured by using `[Authorize]` attribute.

In addition, certain JWT reserved claims will be automatically be populated into `HttpContext.User` as the following Claim Type (from `System.Security.Claims` namespace):

|JWT Claim Name|Data Type     |Claim Type                 |
|--------------|--------------|---------------------------|
|sub           |`string`      |`ClaimTypes.NameIdentifier`|
|email         |`string`      |`ClaimTypes.Email`         |
|unique_name   |`string`      |`ClaimTypes.Name`          |
|roles         |`List<string>`|`ClaimTypes.Role`          |

*This list is anything but complete. There might be more claims that are transformed but not listed yet.*

Therefore, you can use role-based authorization as well, for example: `[Authorize(Roles = "Administrator")]`

If you wish to do more than one type of authentication to separate routes, you should use `app.UseWhen`, for example:

```csharp
public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
{
    app.UseStaticFiles();
    AuthenticateUI(app);
    AuthenticateAPI(app);
    app.UseMvc(routes =>
    {
        routes.MapRoute(
            name: "default",
            template: "{controller=Home}/{action=Index}/{id?}");
    });
}

public void AuthenticateAPI(IApplicationBuilder app)
{
    // IsAPI method returns TRUE when a request route is started with "/api".
    // For those routes, we'll use JWT Authorization:
    app.UseWhen(context => IsAPI(context), builder =>
    {
        builder.UseJwtBearerAuthentication(new JwtBearerOptions
        {
            AutomaticAuthenticate = true,
            TokenValidationParameters = tokenValidationParameters,
        });
    });
}

public void AuthenticateUI(IApplicationBuilder app)
{
    // For non-API routes, we'll use Cookie Authorization, as an example.
    app.UseWhen(context => !IsAPI(context), builder =>
    {
        builder.UseCookieAuthentication(new CookieAuthenticationOptions
        {
            AuthenticationScheme = "Accelist_Identity",
            LoginPath = new PathString("/auth/login"),
            AutomaticAuthenticate = true,
            AutomaticChallenge = true
        });
    });
}
```

### Creating and Using a JWT Token

We can use an MVC web API to accept a request containing a user's credentials in exchange for a JWT token.

```csharp
public class TokenRequest
{
    [Required]
    public string Username { set; get; }

    [Required]
    public string Password { set; get; }
}

[Route("api/v1/token")]
public class TokenApiController : Controller
{
    private readonly AuthService AuthService;

    public TokenApiController(AuthService authService)
    {
        // AuthService is your own class that handles your application's authentication functions.
        // AuthService is injected via Controller's constructor and registered At startup.cs
        // Read more: https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/dependency-injection
        this.AuthService = authService;
    }

    [HttpPost]
    public async Task<IActionResult> Post([FromBody]TokenRequest model)
    {
        if (ModelState.IsValid == false)
        {
            return BadRequest("Username and password must not be empty!");
        }

        // Authenticates username and password to your SQL Server database, for example.
        // If authentication is successful, return a user's claims.
        var claims = await AuthService.TryLogin(model.Username, model.Password);
        if (claims == null)
        {
            return BadRequest("Invalid username or password!");
        }

        // As an example, AuthService.CreateToken can return Jose.JWT.Encode(claims, YourTokenSecretKey, Jose.JwsAlgorithm.HS256);
        var token = AuthService.CreateToken(claims);
        return Ok(token);
    }
}
```

Therefore, by sending a HTTP POST request containing `Username` and `Password` to that endpoint, you will receive a token that is signed by the server.

Example for making a request from the client using JavaScript Promise using [AngularJS](https://angularjs.org/) [$http](https://docs.angularjs.org/api/ng/service/$http):

```javascript
$http.post("/api/v1/token", {
    username: "foo",
    password: "bar"
}).then(function(response) {
    // Request successful.
    MyToken = response.data;
}, function(response) {
    // Request failed! Do something with the response.
});
```

Then later, you can use the obtained token for sending requests to secured routes by attaching it to the request header.

```javascript
$http.post("/api/v1/function", {
    foo: "bar"
}, {
    headers: {
        Authorization: "Bearer " + MyToken
    }
}).then(function(response) {
    // Request successful. Do something with the response.
}, function(response) {
    // Request failed! Do something with the response.
});
```
