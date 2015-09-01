# Ultimate Javascript Object Signing and Encryption (JOSE) and JSON Web Token (JWT) Implementation for .NET

Minimallistic zero-dependency library for generating, decoding and encryption [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10). Supports full suite 
of [JSON Web Algorithms](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31) as of July 4, 2014 version. JSON parsing agnostic, can plug any desired JSON processing library. 
Extensively tested for compatibility with [jose.4.j](https://bitbucket.org/b_c/jose4j/wiki/Home), [Nimbus-JOSE-JWT](https://bitbucket.org/nimbusds/nimbus-jose-jwt/wiki/Home) and [json-jwt](https://github.com/nov/json-jwt) libraries.


* WinRT compatible version (Windows 8.1 and Windows Phone 8.1) is avaliable here: [JoseRT](https://github.com/dvsekhvalnov/jose-rt).

## Foreword
Originally forked from https://github.com/johnsheehan/jwt . Almost re-written from scratch to support JWT encryption capabilities and unified interface for encoding/decoding/encryption 
and other features.
Moved to separate project in February 2014.

AES Key Wrap implementation ideas and test data from http://www.cryptofreak.org/projects/rfc3394/ by Jay Miller

## Supported JWA algorithms

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

##### Notes:
\* It appears that Microsoft CNG implementation of BCryptSecretAgreement/NCryptSecretAgreement contains a bug for calculating Elliptic Curve Diffie–Hellman secret agreement
on keys higher than 256 bit (P-384 and P-521 NIST curves correspondingly). At least produced secret agreements do not match any other implementation in different languages.
Technically it is possible to use ECDH-ES or ECDH-ES+AES Key Wrap family with A192CBC-HS384 and A256CBC-HS512 but most likely produced JWT tokens will not be compatible with other platforms and therefore can't be decoded correctly.

## Installation
### NuGet 
`Install-Package jose-jwt`

### Manual
Grab source and compile yourself. 

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

#### ES-\*  family
ES256, ES384, ES256 ECDSA signatures requires `CngKey` (usually private) elliptic curve key of corresponding length. Normally existing `CngKey` loaded via `CngKey.Open(..)` method from Key Storage Provider.
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

### Creating encrypted Tokens
#### RSA-\* key management family of algorithms
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

**RS256, RS384, RS512**, **PS256, PS384, PS512** signatures and **RSA-OAEP-256**, **RSA-OAEP, RSA1_5** key management algorthms expects `RSACryptoServiceProvider` as a key, public/private is asymmetric to encoding:

```C#
string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";

var privateKey=new X509Certificate2("my-key.p12", "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;

string json = Jose.JWT.Decode(token,privateKey);
```

**ES256, ES284, ES512** signatures, **ECDH-ES** and **ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW** key management algorithms expects `CngKey` as a key, public/private is asymmetric to encoding. If `EccKey.New(...)` wrapper is used, make
sure correct `usage:` value is set. `CngKeyUsages.KeyAgreement` for ECDH-ES and `CngKeyUsages.Signing` for ES-* (default value, can be ommited).

```C#
string token = "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA";

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };

var publicKey=EccKey.New(x, y);

string json = Jose.JWT.Decode(token,publicKey);
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

### Parsing and mapping json to object model directly
jose-jwt library is agnostic about object model used to represent json payload as well as underlying framework used to serialize/parse json objects. Library provides convinient generic methods to work directly with your object model:

```C#
MyDomainObject obj=Jose.JWT.Decode<MyDomainObject>(token,secretKey); //will invoke configured IJsonMapper to perform parsing/mapping of content to MyDomainObject 

string data=Jose.JWT.Encode(obj,secrectKey,JwsAlgorithm.HS256); //for object argument configured IJsonMapper will be invoked to serialize object to json string before encoding
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

Jose.JWT.JsonMapper = new NewtonsoftMapper();
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

Jose.JWT.JsonMapper = new ServiceStackMapper();
```

### More examples
Checkout UnitTests\TestSuite.cs for more examples.