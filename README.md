# Ultimate Javascript Object Signing and Encryption (JOSE), JSON Web Token (JWT), JSON Web Encryption (JWE) and JSON Web Keys (JWK) Implementation for .NET and .NET Core

Minimallistic zero-dependency library for generating, decoding and encryption [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10). Supports full suite
of [JSON Web Algorithms](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31) and [Json Web Keys](https://datatracker.ietf.org/doc/html/rfc7517). JSON parsing agnostic, can plug any desired JSON processing library.
Extensively tested for compatibility with [jose.4.j](https://bitbucket.org/b_c/jose4j/wiki/Home), [Nimbus-JOSE-JWT](https://bitbucket.org/connect2id/nimbus-jose-jwt/wiki/Home) and [json-jwt](https://github.com/nov/json-jwt) libraries.
JWE JSON Serialization cross-tested with [JWCrypto](https://github.com/latchset/jwcrypto/).

## FIPS compliance ##
Library is fully FIPS compliant since v2.1

## Which version?
- v5.1 support for experimental algorithms RSA-OAEP-384, RSA-OAEP-512 and forced strict AES-GCM to avoid trancated tags (see https://github.com/dotnet/runtime/issues/71366)

- v5.0 brings Linux, OSX and FreeBSD compatibility for [ECDH encryption](#ecdh-es-and-ecdh-es-with-aes-key-wrap-key-management-family-of-algorithms) as long as managed `ECDsa` keys support. Fixes cross compatibility issues with encryption over NIST P-384, P-521 curves. And introduces new [security fixes and controls](#customizing-compression).

- v4.1 added additional capabilities to manage runtime avaliable alg suite, see [Customizing library for security](#customizing-library-for-security). And also introduced default max limits for `PBKDF2` (`PBES2-*`) max iterations according to [OWASP PBKDF2 Recomendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).

- v4.0 introduced Json Web Key (JWK), [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) support. Latest stable. All new features will most likely appear based on given version.

- v3.2 dropped `Newtonsoft.Json` support in favor of `System.Text.Json` on `netstandard2.1`

- v3.1 introduced JWE JSON Serialization defined in [RFC 7516](https://tools.ietf.org/html/rfc7516)

- v3.0 and above additionally targets `netstandard2.1` to leverage better .net crypto support on *\*nix* systems and enable more supported algorithms.

- v2.1 and above added extra features support for .NET461+ and coming with 3 version of binaries (`NET4`, `NET461` and `netstandard1.4`).

- v2.0 and above is .NET Core compatible and aimed to support both .NET framework (`NET40`) and .NET Core (`netstandard1.4`) runtimes.

- v1.9 is built against .NET framework only and should be compatible with `NET40` and above. The version is not actively maintained anymore except critical bug fixes.

- WinRT compatible version (Windows 8.1 and Windows Phone 8.1) is avaliable as standalone project here: [jose-rt](https://github.com/dvsekhvalnov/jose-rt).

- PCLCrypto based experimental project living up here: [jose-pcl](https://github.com/dvsekhvalnov/jose-pcl).

## Important upgrade notes
> :warning: **v4 -> v5**:
> - JWK EC keys now bridges to `ECDsa` by default instead of `CngKey` on .net 4.7.2+ and netstandard2.1+
> - `Jwk.ToJson()` / `Jwk.FromJson()` now defaults to `JWT.DefaultSettings.JsonMapper` if not provided explicitly.
> - Deflate decompression is limited to 250Kb by default. Check out [customization section](#customizing-compression) if need more.


> :warning: **v3.0 -> v3.1 stricter argument validation extraHeaders argument**
>
> In 3.1 and above an attempt to override `enc` or `alg` header values in `extraHeaders` will throw `ArgumentException`.

> :warning: **v2 -> v3 update public sdk changes**
>
> Moved:
> - `Security.Cryptography.EccKey` to `Jose.keys.EccKey`
> - `Security.Cryptography.RsaKey` to `Jose.keys.RsaKey`

## OS cross compatibility
| .Net version | Windows | Linux | Mac OS | FreeBSD v14 |
| --- | :---: | :---: | :---: | :---: |
| netcoreapp2.1 | ✅ | ✅ |    |   |
| netcoreapp3.1 | ✅ | ✅ | ✅ |   |
| net 8.0       | ✅ | ✅ | ✅ | ✅ |
| net 5.0       | ✅ | ✅ | ✅ |    |
| net 4.7       | ✅ |   |    |    |
| net 4.6       | ✅ |   |    |    |
| net 4.0       | ✅ |   |    |    |

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
- RSAES OAEP 256, 384, 512 (using SHA-256, 384, 512 and MGF1 with SHA-256, 384, 512) encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
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
- RSAES OAEP 256, 384, 512 (using SHA-256, 384, 512 and MGF1 with SHA-256, 384, 512) encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- RSAES OAEP (using SHA-1 and MGF1 with SHA-1) encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- RSAES-PKCS1-V1_5 encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- Direct symmetric key encryption with pre-shared key A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM and A256GCM
- A128KW, A192KW, A256KW encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- A128GCMKW, A192GCMKW, A256GCMKW encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- ECDH-ES<sup>\*</sup> with A128CBC-HS256, A128GCM, A192GCM, A256GCM
- ECDH-ES+A128KW<sup>\*</sup>, ECDH-ES+A192KW<sup>\*</sup>, ECDH-ES+A256KW<sup>\*</sup> with A128CBC-HS256, A128GCM, A192GCM, A256GCM

**Compression**

- DEFLATE compression

## Json Web Key (JWK)

- RSA, EC, Oct keys
- X509 Chains, SHA1 & SHA2 thumbprints



##### Notes:
* Types returned by crytographic methods MAY be different on Windows and Linux. e.g. GetRSAPrivateKey() on X509Certificate2 on Windows returns RsaCng and OpenSslRsa on *nix.
* It appears that Microsoft CNG implementation of BCryptSecretAgreement/NCryptSecretAgreement contains a bug for calculating Elliptic Curve Diffie-Hellman secret agreement
on keys higher than 256 bit (P-384 and P-521 NIST curves correspondingly). At least produced secret agreements do not match any other implementation in different languages. Starting version 5 we **not recommending** usage of `CngKey` keys with ECDH-ES family due to cross compatibility with other libraries.
Please switch to use `ECDsa`, `ECDiffieHellman` or `JWK` instead, which are **cross compatible** on all curves and operating systems.

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

**Warning:** When using a `class` as the data structure of the payload, always use nullable data types for its properties. [details](#potential-security-risk)

### Creating signed Tokens
#### HS-\* family
HS256, HS384, HS512 signatures require `byte[]` array key or `Jwk` key of type `oct` of corresponding length

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string token=Jose.JWT.Encode(payload, secretKey, JwsAlgorithm.HS256);
```

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

Jwk key = new Jwk(new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234});

string token=Jose.JWT.Encode(payload, key, JwsAlgorithm.HS256);
```

#### RS-\* and PS-\* family
**NET40-NET45**:

RS256, RS384, RS512 and PS256, PS384, PS512 signatures require `RSACryptoServiceProvider` (usually private) key of corresponding length. CSP need to be forced to use Microsoft Enhanced RSA and AES Cryptographic Provider.
Which usually can be done be re-importing RSAParameters. See http://clrsecurity.codeplex.com/discussions/243156 for details.

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var privateKey=new X509Certificate2("my-key.p12", "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;

string token=Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.RS256);
```

**NETCORE**:
RS256, RS384, RS512 and PS256, PS384, PS512 signatures require `RSA` (usually private) or `Jwk` key of type `RSA` of corresponding length.

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var privateKey=new X509Certificate2("my-key.p12", "password").GetRSAPrivateKey();

string token=Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.RS256);
```

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

Jwk privateKey = new Jwk(
    e: "AQAB",
    n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q",
    p: "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts",
    q: "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s",
    d: "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ",
    dp: "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M",
    dq: "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU",
    qi: "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g"
);

string token=Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.RS256);

```
**NET461 and above**:
Accepts `RSACryptoServiceProvider`, `RSA` or `Jwk` types of keys (see above).


#### ES-\*  family
**NET40-NET45**:
ES256, ES384, ES512 ECDSA signatures requires `CngKey` (usually private) elliptic curve key of corresponding length. Normally existing `CngKey` loaded via `CngKey.Open(..)` method from Key Storage Provider.
But if you want to use raw key material (x,y) and d, jose-jwt provides convenient helper `EccKey.New(x,y,d)`.

``` cs
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
ES256, ES384, ES512 ECDSA signatures can accept either `CngKey`(see above), `ECDsa` (usually private)  or `Jwk` of type `EC` elliptic curve key of corresponding length.

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var privateKey=new X509Certificate2("ecc-key.p12", "password").GetECDsaPrivateKey();

string token=Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.ES256);
```

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var privateKey = new Jwk(
    crv: "P-256",
    x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
    y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
    d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
);

string token=Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.ES256);
```

**NET461 and above**:
Accepts `CngKey`, `ECDsa` and `Jwk` types of keys (see above).


### Creating encrypted Tokens
#### RSA-\* key management family of algorithms

**NET40-NET45**:

RSA-OAEP-256, RSA-OAEP-384, RSA-OAEP-512, RSA-OAEP and RSA1_5 key management requires `RSACryptoServiceProvider` (usually public) key of corresponding length.

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
RSA-OAEP-256, RSA-OAEP-384, RSA-OAEP-512, RSA-OAEP and RSA1_5 key management requires `RSA` (usually public) or `Jwk` key of type `RSA` of corresponding length.

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var publicKey=new X509Certificate2("my-key.p12", "password").GetRSAPublicKey();

string token = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM);
```

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

Jwk publicKey = new Jwk("AQAB", "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q");

string token = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM);
```

**NET461**:
Accepts `RSACryptoServiceProvider`, `RSA`, `Jwk` (see above) and `CngKey` types of keys.

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

CngKey publicKey = CngKey.Open("connectionKeyId", CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey));

string token = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM);
```

#### DIR direct pre-shared symmetric key family of algorithms
Direct key management with pre-shared symmetric keys requires `byte[]` array or `Jwk` of type `oct` key of corresponding length

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string token = Jose.JWT.Encode(payload, secretKey, JweAlgorithm.DIR, JweEncryption.A128CBC_HS256);
```

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new Jwk(new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234});

string token = Jose.JWT.Encode(payload, secretKey, JweAlgorithm.DIR, JweEncryption.A128CBC_HS256);
```

#### AES Key Wrap key management family of algorithms
AES128KW, AES192KW and AES256KW key management requires `byte[]` array or `Jwk` of type `oct` key of corresponding length

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string token = Jose.JWT.Encode(payload, secretKey, JweAlgorithm.A256KW, JweEncryption.A256CBC_HS512);
```

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new Jwk(new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234});

string token = Jose.JWT.Encode(payload, secretKey, JweAlgorithm.A256KW, JweEncryption.A256CBC_HS512);
```

#### AES GCM Key Wrap key management family of algorithms
AES128GCMKW, AES192GCMKW and AES256GCMKW key management requires `byte[]` array or `Jwk` of type `oct` key of corresponding length

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string token = Jose.JWT.Encode(payload, secretKey, JweAlgorithm.A256GCMKW, JweEncryption.A256CBC_HS512);
```

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var secretKey = new Jwk(new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234});

string token = Jose.JWT.Encode(payload, secretKey, JweAlgorithm.A256GCMKW, JweEncryption.A256CBC_HS512);
```

#### ECDH-ES and ECDH-ES with AES Key Wrap key management family of algorithms
**NET40-NET46 (windows only)**:
ECDH-ES and ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW key management requires `CngKey` (usually public) or `Jwk` of type `EC` elliptic curve key of corresponding length.

Normally existing `CngKey` can be loaded via `CngKey.Open(..)` method from Key Storage Provider.
But if you want to use raw key material (x,y) and d, jose-jwt provides convenient helper `EccKey.New(x,y,usage:CngKeyUsages.KeyAgreement)` or use `Jwk` instead.

`Jwk` keys will use transparent bridging to `CngKey` under the hood.

``` cs
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

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

var publicKey = new Jwk(
    crv: "P-256",
    x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
    y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU"
);

string token = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.ECDH_ES, JweEncryption.A256GCM);
```

**NET472 or NETCORE (all OS)**:
Accepts either `CngKey`, `Jwk` of type EC (see above) or additionally `ECDsa` and `ECDiffieHellman` as a key.

`Jwk` keys will use transparent bridging to `ECDiffieHellman` under the hood.

`jose-jwt` provides convenient helper `EcdhKey.New(x,y,usage:CngKeyUsages.KeyAgreement)` if one want to to constuct `ECDiffieHellman` using raw key material (x,y) and d.

`ECDsa` keys usually loaded from files.

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

ECDsa publicKey = new X509Certificate2("ecc384.p12", "<password>").GetECDsaPublicKey();

string token = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.ECDH_ES_A192KW, JweEncryption.A192GCM);
```

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };

ECDiffieHellman publicKey=EcdhKey.New(x, y, usage:CngKeyUsages.KeyAgreement);

string token = Jose.JWT.Encode(payload, publicKey, JweAlgorithm.ECDH_ES_A128KW, JweEncryption.A128GCM);
```


#### PBES2 using HMAC SHA with AES Key Wrap key management family of algorithms
PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW key management requires `string` passphrase to derive key from

``` cs
var payload = new Dictionary<string, object>()
{
    { "sub", "mr.x@contoso.com" },
    { "exp", 1300819380 }
};

string token = Jose.JWT.Encode(payload, "top secret", JweAlgorithm.PBES2_HS256_A128KW, JweEncryption.A256CBC_HS512);
```

Iteration counts can be controlled by setting `p2c` header value:
```c#
var headers = new Dictionary<string, object>
{
    { "p2c", 10000 }
};

string token = Jose.JWT.Encode(payload, "top secret", JweAlgorithm.PBES2_HS256_A128KW, JweEncryption.A256CBC_HS512, extraHeaders: headers);
```

Please see [Adding extra headers](#adding-extra-headers) for additional details.


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
#### What methods to use?
Historically `jose-jwt` provided single family of `Decode()` methods that handles both signed and encrypted tokens with uniform interface, but as a number of confusion attacks on JWT libraries increased over last years, starting v5 library additionally provides dedicated methods `Verify()` and `Encrypt()` that are limited in scope to verifying signatures and decrypting tokens accordingly. See [Strict Validation](#strict-validation) and [Confusion Attacks](#confusion-attacks-and-how-to-nail-them) sections for more information.

Decoding json web tokens is fully symmetric to creating signed or encrypted tokens:

**HS256, HS384, HS512** signatures, **A128KW, A192KW, A256KW**, **A128GCMKW, A192GCMKW, A256GCMKW** and **DIR** key management algorithms expects `byte[]` array or `Jwk` of type `oct` key

``` cs
string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg";

byte[] secretKey=new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string json = Jose.JWT.Decode(token, secretKey);

// starting v5 can also
string json=Jose.JWT.Decrypt(token, secretKey);
```

``` cs
string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg";

byte[] secretKey=new Jwk(new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234});

string json = Jose.JWT.Decode(token, secretKey);

// starting v5 can also
string json = Jose.JWT.Decrypt(token, secretKey);
```

**RS256, RS384, RS512**, **PS256, PS384, PS512** signatures and **RSA-OAEP-256**, **RSA-OAEP-384**, **RSA-OAEP-512**, **RSA-OAEP, RSA1_5** key management algorithms expects

**NET40-NET45**: `RSACryptoServiceProvider` as a key, public/private is asymmetric to encoding:

``` cs
string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";

var privateKey=new X509Certificate2("my-key.p12", "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;

string json = Jose.JWT.Decode(token,privateKey);

// starting v5 can also
string json = Jose.JWT.Decrypt(token, secretKey);
```

**NETCORE**: `RSA` or `Jwk` of type `RSA` as a key, public/private is asymmetric to encoding:
``` cs
string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";

var privateKey=new X509Certificate2("my-key.p12", "password").GetRSAPrivateKey();

string json = Jose.JWT.Decode(token,privateKey);

// starting v5 can also
string json = Jose.JWT.Decrypt(token, secretKey);
```

``` cs
string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";

Jwk privateKey = new Jwk(
    e: "AQAB",
    n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q",
    p: "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts",
    q: "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s",
    d: "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ",
    dp: "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M",
    dq: "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU",
    qi: "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g"
);

string json = Jose.JWT.Decode(token,privateKey);

// starting v5 can also
string json = Jose.JWT.Decrypt(token, secretKey);
```

**NET461**: `RSACryptoServiceProvider`, `RSA`, `Jwk` of type `RSA` (see above) or `CngKey` types of keys, public/private is asymmetric to encoding.

``` cs
string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";

CngKey privateKey = CngKey.Open("decryptionKeyId", CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey));

string json = Jose.JWT.Decode(token,privateKey);

// starting v5 can also
string json = Jose.JWT.Decrypt(token, secretKey);
```

**ES256, ES284, ES512** signatures expects

**NET40-NET45**: `CngKey` as a key, public/private is asymmetric to encoding. If `EccKey.New(...)` wrapper is used, make
sure correct `usage:` value is set. Should be `CngKeyUsages.Signing` for ES-* signatures (default value, can be ommited).

``` cs
string token = "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA";

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };

var publicKey=EccKey.New(x, y);

string json = Jose.JWT.Decode(token, publicKey);

// starting v5 can also
string json = Jose.JWT.Verify(token, secretKey);
```

**NETCORE**: can accept either `CngKey` (see above), `ECDsa` or `Jwk` of type `EC` as a key, public/private is asymmetric to encoding.

``` cs
string token = "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA";

var publicKey=new X509Certificate2("ecc-key.p12", "password").GetECDsaPublicKey();

string token=Jose.JWT.Decode(token, publicKey, JwsAlgorithm.ES256);

// starting v5 can also
string json = Jose.JWT.Verify(token, secretKey);
```

``` cs
string token = "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA";

var publicKey = new Jwk(
    crv: "P-256",
    x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
    y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU"
);

string token=Jose.JWT.Decode(token, publicKey, JwsAlgorithm.ES256);

// starting v5 can also
string json = Jose.JWT.Verify(token, secretKey);
```

**NET461**: accepts `CngKey`, `ECDsa` or `Jwk` of type `EC` types of keys (see examples above), public/private is asymmetric to encoding.


**ECDH-ES** and **ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW** key management algorithms expects

**NET40-NET46 (windows only)**:  `CngKey` or `Jwk` of type `EC` as a key, public/private is asymmetric to encoding. If `EccKey.New(...)` wrapper is used, make
sure correct `usage:` value is set. Should be `CngKeyUsages.KeyAgreement` for ECDH-ES.

`Jwk` keys will use transparent bridging to `CngKey` under the hood.

``` cs
string token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJPbDdqSWk4SDFpRTFrcnZRTmFQeGp5LXEtY3pQME40RVdPM1I3NTg0aEdVIiwieSI6Ik1kU2V1OVNudWtwOWxLZGU5clVuYmp4a3ozbV9kTWpqQXc5NFd3Q0xaa3MiLCJjcnYiOiJQLTI1NiJ9fQ..E4XwpWZ2kO-Vg0xb.lP5LWPlabtmzS-m2EPGhlPGgllLNhI5OF2nAbbV9tVvtCckKpt358IQNRk-W8-JNL9SsLdWmVUMplrw-GO-KA2qwxEeh_8-muYCw3qfdhVVhLnOF-kL4mW9a00Xls_6nIZponGrqpHCwRQM5aSr365kqTNpfOnXgJTKG2459nqv8n4oSfmwV2iRUBlXEgTO-1Tvrq9doDwZCCHj__JKvbuPfyRBp5T7d-QJio0XRF1TO4QY36GtKMXWR264lS7g-T1xxtA.vFevA9zsyOnNA5RZanKqHA";

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

var privateKey=EccKey.New(x, y, d, CngKeyUsages.KeyAgreement);

string json = Jose.JWT.Decode(token, privateKey);

// starting v5 can also
string json = Jose.JWT.Decrypt(token, secretKey);
```

``` cs
string token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJPbDdqSWk4SDFpRTFrcnZRTmFQeGp5LXEtY3pQME40RVdPM1I3NTg0aEdVIiwieSI6Ik1kU2V1OVNudWtwOWxLZGU5clVuYmp4a3ozbV9kTWpqQXc5NFd3Q0xaa3MiLCJjcnYiOiJQLTI1NiJ9fQ..E4XwpWZ2kO-Vg0xb.lP5LWPlabtmzS-m2EPGhlPGgllLNhI5OF2nAbbV9tVvtCckKpt358IQNRk-W8-JNL9SsLdWmVUMplrw-GO-KA2qwxEeh_8-muYCw3qfdhVVhLnOF-kL4mW9a00Xls_6nIZponGrqpHCwRQM5aSr365kqTNpfOnXgJTKG2459nqv8n4oSfmwV2iRUBlXEgTO-1Tvrq9doDwZCCHj__JKvbuPfyRBp5T7d-QJio0XRF1TO4QY36GtKMXWR264lS7g-T1xxtA.vFevA9zsyOnNA5RZanKqHA";

var privateKey = new Jwk(
        crv: "P-256",
        x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
        y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
        d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
);

string json = Jose.JWT.Decode(token, privateKey);

// starting v5 can also
string json = Jose.JWT.Decrypt(token, secretKey);
```

**NET472 or NETCORE (all OS)**:
Accepts either `CngKey`, `Jwk` of type EC (see above) or additionally `ECDsa` and `ECDiffieHellman` as a key.

`Jwk` keys will use transparent bridging to `ECDiffieHellman` under the hood.

``` cs
string token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJPbDdqSWk4SDFpRTFrcnZRTmFQeGp5LXEtY3pQME40RVdPM1I3NTg0aEdVIiwieSI6Ik1kU2V1OVNudWtwOWxLZGU5clVuYmp4a3ozbV9kTWpqQXc5NFd3Q0xaa3MiLCJjcnYiOiJQLTI1NiJ9fQ..E4XwpWZ2kO-Vg0xb.lP5LWPlabtmzS-m2EPGhlPGgllLNhI5OF2nAbbV9tVvtCckKpt358IQNRk-W8-JNL9SsLdWmVUMplrw-GO-KA2qwxEeh_8-muYCw3qfdhVVhLnOF-kL4mW9a00Xls_6nIZponGrqpHCwRQM5aSr365kqTNpfOnXgJTKG2459nqv8n4oSfmwV2iRUBlXEgTO-1Tvrq9doDwZCCHj__JKvbuPfyRBp5T7d-QJio0XRF1TO4QY36GtKMXWR264lS7g-T1xxtA.vFevA9zsyOnNA5RZanKqHA";

ECDsa privateKey = new X509Certificate2("ecc256.p12", "<password>").GetECDsaPrivateKey();

string token = Jose.JWT.Decode(token, privateKey);

// starting v5 can also
string json = Jose.JWT.Decrypt(token, secretKey);
```

``` cs
string token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJPbDdqSWk4SDFpRTFrcnZRTmFQeGp5LXEtY3pQME40RVdPM1I3NTg0aEdVIiwieSI6Ik1kU2V1OVNudWtwOWxLZGU5clVuYmp4a3ozbV9kTWpqQXc5NFd3Q0xaa3MiLCJjcnYiOiJQLTI1NiJ9fQ..E4XwpWZ2kO-Vg0xb.lP5LWPlabtmzS-m2EPGhlPGgllLNhI5OF2nAbbV9tVvtCckKpt358IQNRk-W8-JNL9SsLdWmVUMplrw-GO-KA2qwxEeh_8-muYCw3qfdhVVhLnOF-kL4mW9a00Xls_6nIZponGrqpHCwRQM5aSr365kqTNpfOnXgJTKG2459nqv8n4oSfmwV2iRUBlXEgTO-1Tvrq9doDwZCCHj__JKvbuPfyRBp5T7d-QJio0XRF1TO4QY36GtKMXWR264lS7g-T1xxtA.vFevA9zsyOnNA5RZanKqHA";

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

var privateKey=EcdhKey.New(x, y, d, CngKeyUsages.KeyAgreement);

string json = Jose.JWT.Decode(token, privateKey);

// starting v5 can also
string json = Jose.JWT.Decrypt(token, secretKey);
```


**PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW** key management algorithms expects `string` passpharase as a key

```C#
string token = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo4MTkyLCJwMnMiOiJiMFlFVmxMemtaNW9UUjBMIn0.dhPAhJ9kmaEbP-02VtEoPOF2QSEYM5085V6zYt1U1qIlVNRcHTGDgQ.4QAAq0dVQT41dQKDG7dhRA.H9MgJmesbU1ow6GCa0lEMwv8A_sHvgaWKkaMcdoj_z6O8LaMSgquxA-G85R_5hEILnHUnFllNJ48oJY7VmAJw0BQW73dMnn58u161S6Ftq7Mjxxq7bcksWvFTVtG5RsqqYSol5BZz5xm8Fcj-y5BMYMvrsCyQhYdeGEHkAvwzRdvZ8pGMsU2XPzl6GqxGjjuRh2vApAeNrj6MwKuD-k6AR0MH46EiNkVCmMkd2w8CNAXjJe9z97zky93xbxlOLozaC3NBRO2Q4bmdGdRg5y4Ew.xNqRi0ouQd7uo5UrPraedg";

string json = Jose.JWT.Decode(token, "top secret");

// starting v5 can also
string json = Jose.JWT.Decrypt(token, secretKey);
```

### JWE JSON Serialization support (RFC 7516)
As of version v3.1 `jose-jwt` library provides full support for json serialized encrypted content.

#### Decoding json serialized encrypted content

`JweToken Jose.JWE.Decrypt(token, key)` - can be used to decrypt JSON serialized token.

See [Verifying and Decoding Tokens](#verifying-and-decoding-tokens) section for information about different key types usage.

The function returns object of type `JweToken` with following properties:
* `PlaintextBytes` - byte array with decrypted content, only when decryption successfully performed
* `Plaintext` - decrypted content as string, only when decryption successfully performed
* `Recipient` - effective recipient that was used to decrypt token, only when decryption was successfully performed
* `Aad` - additional authentication data
* `Iv` - initialization vector
* `Ciphertext` - ciphertext (encrypted content)
* `AuthTag` - authenication tag
* `UnprotectedHeader` - shared unprotected headers (key-value pairs)
* `ProtectedHeaderBytes` - shared signature protected headers, binary blob
* `Recipients` - list of `JweRecipient` objects as specified in token

`JweRecipient` object supports following properties:
* `Alg` - Key encryption algorithm
* `Header` - Per recipient set of headers
* `JoseHeader` - effective headers for given recipient, calculated as union of shared headers and per-recipient headers, only when decryption successfully performed via `Jose.JWE.Decrypt()` or `Jose.JWE.Headers()` was called.


``` cs
string token = @"
{
	""aad"": ""ZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4w"",
	""ciphertext"": ""02VvoX1sUsmFi2ZpIbTI8g"",
	""encrypted_key"": ""kH4te-O3DNZoDlxeDnBXM9CNx2d5IgVGO-cVMmqTRW_ws0EG_RKDQ7FLLztMM83z2s-pSNSZtFf3bx9Aky8XOzhIYCIU7XvmiQ0pp5z1FRdrwO-RxEOJfb2hAjD-hE5lCJkkY722QGs4IrUQ5N5Atc9h9-0vDcg-gksFIuaLMeRQj3LxivhwJO-QWFd6sG0FY6fBCwS1X6zsrZo-m9DNvrB6FhMpkLPBDOlCNnjKf1_Mz_jAuXIwnVUhoq59m8tvxQY1Fyngiug6zSnM207-0BTXzuCTnPgPAwGWGDLO7o0ttPT6RI_tLvYE6AuOynsqsHDaecyIkJ26dif3iRmkeg"",
	""header"": {
		""alg"": ""RSA-OAEP-256"",
		""kid"": ""Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc""
	},
	""iv"": ""E1BAiqIeAH_0eInT59zb8w"",
	""protected"": ""eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldFIn0"",
	""tag"": ""yYBiajF5oMtyK3mRVQyPnlJL25hXW8Ct8ZMcFK5ehDY""
}";

// Use key type approporiate for your recipient
var key = LoadPrivateRsaKey();

// decrypt JSON serialized token
JweToken jwe = Jose.JWE.Decrypt(token, key);

// generic form to access decrypted content as blob
byte[] binaryContent = jwe.PlaintextBytes;

// convinient helper to get decrypted content as string
string content = jwe.Plaintext;

// effective recipient information that was used for decryption
JweRecipient recipient = jwe.Recipient;

// accessing effective headers
string keyId = recipient.JoseHeaders["kid"];
```

#### Encrypting using JSON serialization
`string Jose.JWE.Encrypt(plaintext, recipients, encryption, add, serialization, compression, extraProtectedHeaders, unprotectedHeaders, settings)` - can be used to encrypt string content and produce JSON serialized token.

Alternate version to encrypt binary content is also available `string Jose.JWE.EncryptBytes()`.

Where:
* `plaintext` - content (payload) to be encrypted
* `recipients` - one or more recipients information
* `encryption` - encryption to be used
* `add` - optional, Additional Authentication Data
* `serialization` - optional, `Json` is default, final token encoding
* `compression` - optional, compression algorithm
* `extraProtectedHeaders` - optional, additional key-value pairs to include into protected header
* `unprotectedHeaders` - optional, key-value pairs to include into unprotected header

See [Creating encrypted Tokens](#creating-encrypted-tokens) section for information about different key types usage.

``` cs
var payload = "Hello JWE !";
var blob = new byte[] { 72, 101, 108, 108, 111, 32, 74, 87, 69, 32, 33 };
var preSharedKey = LoadKey();

// generate JSON encoded token
string token_1 = JWE.Encrypt(payload, new[] { new JweRecipient(JweAlgorithm.A256KW, preSharedKey) }, JweEncryption.A256GCM);

// encrypt binary
string token_2 = JWE.EncryptBytes(payload, new[] { new JweRecipient(JweAlgorithm.A256KW, preSharedKey) }, JweEncryption.A256GCM);

// can opt-in for Compact encoded tokens with same interface
string token_3 = JWE.Encrypt(payload, new[] { new JweRecipient(JweAlgorithm.A256KW, preSharedKey), mode: SerializationMode.Compact }, JweEncryption.A256GCM);
```

Encrypt for multiple recipients at once:
``` cs
var payload = "Hello World !";
JweRecipient r1 = new JweRecipient(JweAlgorithm.PBES2_HS256_A128KW, "secret");
JweRecipient r2 = new JweRecipient(JweAlgorithm.ECDH_ES_A128KW, ECPublicKey());
JweRecipient r3 = new JweRecipient(JweAlgorithm.RSA_OAEP_256, RsaPublicKey());

string token = JWE.Encrypt(payload, new[] { r1, r2, r3 }, JweEncryption.A256GCM);
```

Provide additional authentication data and unprotected shared headers:

``` cs
var payload = "Hello World !";

// additional authenticatin data
var aad = new byte[] { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48 };

// shared unprotected headers
var unprotected = new Dictionary<string, object>
{
    { "jku", "https://server.example.com/keys.jwks" }
};

var preSharedKey = LoadKey();

string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, aad, unprotectedHeaders: unprotected);

```

### Working with Json Web Keys (JWKs)
As of v4.0.0 library provides full-blown support for Json Web Keys (aka [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)), including parsing, contructing and bridging the gap with different .NET key types to be used in all signing and encryption algorithms.

See [Creating encrypted Tokens](#creating-encrypted-tokens), [Creating signed Tokens](#creating-signed-tokens) and [Verifying and Decoding Tokens](#verifying-and-decoding-tokens) for details on using JWK with different Json Web Tokens algorithms.

Most of JWK support will work on `.NET 4.6.1` and `.NET Core 2.0`. But some key bridging requires `.NET 4.7.2` or `NETSTANDARD 2.1` and above.

The two core classes are:

* `Jwk` - object model for Json Web Key
* `JwkSet` - object model Json Web Key Set

### Reading JWK
Both classes offers set of static methods to read or write model from JSON string or dictionary object respectively.
* `Jwk.FromJson(string, IJsonMapper), JwkSet.FromJson(string, IJsonMapper)` - parses json and constructs object model from it
* `Jwk.FromDictionary(IDictionary<string, object>), JwkSet.FromDictionary(IDictionary<string, object>)` - constructs object model from dictionary
* `Jwk.ToJson(IJsonMapper), JwkSet.ToJson(IJsonMapper)` - searializes model to json
* `Jwk.ToDictionary(), JwkSet.ToDictionary()` - writes model as dictionary

See [Examples](#examples) for usage details.

### Constructing JWK
Model object can be constructed normal way via setting approporiate properties or calling collection methods, there are also set of convinient constructors:

``` cs
// Oct key
Jwk octKey = new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

// RSA key
Jwk rsaKey = new Jwk(
    e: "AQAB",
    n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q",
    p: "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts",
    q: "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s",
    d: "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ",
    dp: "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M",
    dq: "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU",
    qi: "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g"
);

// EC key
Jwk eccKey = new Jwk(
    crv: "P-256",
    x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
    y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
    d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
);

// Key sets
JwkSet keySet = new JwkSet(octKey, rsaKey);
keySet.Add(eccKey);
```

### Converting between JWK and .NET key types
Library provides two way bridging with different .NET key types.
One can construct `Jwk` from underlying `ECDsa`, `RSA` or `CngKey` (elliptic keys only)

``` cs
// Cng keys
CngKey eccCngKey = CngKey.Open(...);
Jwk jwk = new Jwk(eccCngKey, isPrivate: false); //or 'true' by defaut

// RSA keys
RSA rsaKey=new X509Certificate2("my-key.p12", "password").GetRSAPublicKey();
Jwk jwk = new Jwk(rsaKey, isPrivate: false); //or 'true' by defaut

// ECDsa keys
ECDsa ecdsaKey = new X509Certificate2("ecc521.p12", "password").GetECDsaPublicKey();
Jwk jwk = new Jwk(ecdsaKey, isPrivate: false); //or 'true' by defaut
```

or convert `Jwk` key to corresponding `ECDsa`, `RSA` or `CngKey` (elliptic keys only)

``` cs
// Returns ephemeral exportable CngKey, handle is cached for subsequent calls
CngKey cngKey = jwk.CngKey(usage: CngKeyUsages.KeyAgreement); // or 'CngKeyUsages.Signing' by default

// Returns backing ECDsa key, constructs new on demand, cached for subsequent calls
ECDsa ecdaKey = jwk.ECDsaKey();

// Returns backing RSA key, constructs new on demand, cached for subsequent calls
RSA rsaKey = jwk.RsaKey();
```

### Working with certificate chains
Direct interface with `X509Certificate2` class is provided when working with chains in JWK:

``` cs
X509Certificate2 root = new X509Certificate2("root.p12");
X509Certificate2 intermidiary = new X509Certificate2("inter.p12");
X509Certificate2 signing = new X509Certificate2("signing.p12");

Jwk key = new Jwk();

// set chain at once
key.SetX509Chain(new List<X509Certificate2>{ root, intermidiary });

// or add one by one
key.Add(signing);

// Read chain from key as list of certificates
List<X509Certificate2> test = key.GetX509Chain();
```

Helpers to set SHA-1 and SHA-256 thumbprints:
``` cs
X509Certificate2 signing = new X509Certificate2("signing.p12");

Jwk key = new Jwk();

// Calculate and set certificate SHA-1 thumbprint
key.SetX5T(signing);

// Calculate and set certificate SHA-256 thumbprint
key.SetX5TSha256(signing);
```

### Extra params
In addition to named params from [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) library allows to include any custom key value params to the key objects:

``` cs
Jwk key = new Jwk();

// add custom params
key.OtherParams = new Dictionary<string, object>();
key.OtherParams["s"] = "2WCTcJZ1Rvd_CJuJripQ1w";
key.OtherParams["c"] = 4096;

// or read them from the key same way
string s = (string)key.OtherParams["s"];
```

### Searching JwkSet with Linq
`JwkSet` is Linq compatible and it is preffered way to locate keys of interest within collection:

``` cs
JwkSet keySet = new JwkSet(....);

IEnumerable<Jwk> rsaKeys =
    from key in keySet
    where key.Alg == "enc" && key.Kty == Jwk.KeyTypes.RSA
    select key;
```

### Examples
1. Decrypt symmetric JWK of Oct type from payload and use it for further signing:

``` cs
    string token = "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMmMiOjgxOTIsInAycyI6Inp3eUF0TElqTXpQM01pQ0giLCJlbmMiOiJBMjU2R0NNIn0.4geBbNNUErAkSiNmUVL23tnH3Jah0B0QkvhAaEcHeUgxRGKmWvkOjg.CCNy7C1HOH-qq5Lo.Uzi9FZ_b8bHenXF7h-D63gZCASdvLA7WqnKRSXwsr7G94SnB5bHiZrUT.l6D2hJSoFPpnXPXLyOloxg";

    // Decrypt symmetric key in payload with PBES2
    Jwk key = Jose.JWT.Decode<Jwk>(token, "secret");

    // And use it to sign new messages
    string signed = JWT.Encode(@"{""hello"": ""world""}", key, JwsAlgorithm.HS512);
```

2. Use Jwk from token header for verification
``` cs
string token = "eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiJxRlp2MHBlYV9qbjVNbzRxRVVtU3R1aGx1bHNvOG4xaW5YYkVvdGRfelRyUXA5SzBSSzBoZjd0MEs0QmpLVmhhaXFJYW00dFZWUXZrbVllQmVZcjFNbW5PXzBOOTdkTUJ6XzdmbXZ5djBoZ0hhQmRRNW1SNXUzTFRsSG84dGpSRTctR3pabUdzNmpNY3lqN0hiWG9iRFBRSlpwcU55NkpqbGlEVlh4VzhuV0pEZXR4R0JscW1UajFFMWZyMlJDc1pMcmVET1BTREllZEcxdXB6OVJyYVNoc0lEemVlZk9jS2liY0FhS2VlVkkzcmtBVThfbU9hdUxTWHYzN2hsazBoNnNTdEpiM3FaUVh5T1VrVmtqWElraHZOdV92ZTB2N0xpTFQ0R19PeFlHenBPUWNDbmltS2RvanpOUDZHdFZEYU1QaC1Ra1NKRTMyVUNvczlSM3dJMlEifX0.eyJoZWxsbyI6ICJ3b3JsZCJ9.BX7lG2iQvYM7vO_DTsPPWbuTTpBP9dsDmEITd_Ofq9Ds8ucWrDVUjlMHBXUCfgTuoHHfeNtFE7sfuLxd0RseEY2Q4OnoFyJC_Gc63DwhrEvzY09i_sTTskc5rfQK9s32K595WjIceWnJh6s03dVEPmBWl_xwihV56LRzy4m8c15d1ZMlNByjpLibPGSVoJT4ae64Ux25hhbEageO-6gsTaYH9zofP3WGUzGf5PGq6nBtmrlQgyPhTkxzB1DUUBx0cA5IpnzQLwEDljKrgKRGn86TUrQc5dlIIKETZcTCnF2-CXq3oiqF81oEkFxfcW2yX5H0kmZmY_dQkKs1JR65yA";

// Grab 'jwk' header
var headers = Jose.JWT.Headers(token);

// And turn it into key
Jwk publicKey = Jwk.FromDictionary(
    (IDictionary<string, object>)headers["jwk"]
);

// ATTENTION: always ensure this is the key you know and expect from partner
// EnsureKnownKey(publicKey);

// Use it to decode payload and verify signature
string payload = Jose.JWT.Decode(token, publicKey);
```

3. Fetching key set from jwks endpoint and locating verification one by thumbprint:

``` cs
HttpClient client = new HttpClient()

// Grab public keys from partner endpoint
string keys = await client.GetStringAsync("https://acme.com/.well-known/jwks.json");

JwkSet jwks = JwkSet.FromJson(keys, JWT.DefaultSettings.JsonMapper);

// Get hint from token headers
var headers = Jose.JWT.Headers(token);

// Find matching public key by thumbprint
Jwk pubKey = (
    from key in jwks
    where key.Alg == Jwk.KeyUsage.Signature &&
            key.KeyOps != null && key.KeyOps.Contains(Jwk.KeyOperations.Verify) &&
            key.Kty == Jwk.KeyTypes.RSA &&
            key.X5T == (string)headers["x5t"]
    select key
).First();

// Finally verify token
var payload = Jose.JWT.Decode(token, pubKey);
```


## Additional utilities

### Unencoded and detached content (aka [RFC 7797](https://tools.ietf.org/html/rfc7797))
As of v2.5.0 library support `b64` header to control payload decoding and encoding and optional content detaching.

Encoding can be controlled with optional `JwtOptions` parameter, that support:
* `DetachPayload` - whether we'd like to omit payload part in token produced (`false` by default)
* `EncodePayload` - whether to apply base64url encoding to payload part (`true` by default)

Options can be mixed in any combinations. To match RFC 7797:

```C#
string token = Jose.JWT.Encode(json, secretKey, JwsAlgorithm.HS256, options: new JwtOptions { DetachPayload = true, EncodePayload = false});
```
or just skip payload for instance:

```C#
string token = Jose.JWT.Encode(json, secretKey, JwsAlgorithm.HS256, options: new JwtOptions { DetachPayload = true });
```

Decoding automatically respect `b64` header if present. In case of detached payload one can provide optional `payload` param:

```C#
string token = "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJSUzI1NiJ9..iyormYw6b0zKjx4K-fpeZO8xrLghkeUFMb2l4alz03CRLVdlXkdeKVG7N5lBbS-kXB4-8hH1ELFA5fUJzN2QYR6ZZIWjDF77HYTw7lsyjTJDNABjBFn-BIXlWatjNdgtRi2BZg2q_Wos87ZQT6Sl-h5hvxsFEsR0kGPMQ4Fjp-sxOyfnls8jAlziqmkpN-K6I3tK2vCLCQgnaN9sYrsIcrzuEA30YeXsgUe3m44yxLCXczXWKE3kgGiZ0MRpVvKOZt4B2DZLcRmNArhxjhWWd1nKZvv8c7kN0TqOjcNEUGWzwDs4ikCSz1aYKaLPXgjzpKnzbajUM117F3aCAaWH9g";

// will echo provided payload back as return value, for consistency
string json = Jose.JWT.Decode(token, PubKey(), payload: @"{""hello"": ""world""}");

// as of v5 can also be used with Verify:
string json = Jose.JWT.Verify(token, PubKey(), payload: @"{""hello"": ""world""}");
```

also works with binary payloads:

```C#
string token = "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJSUzI1NiJ9..ToCewDcERVLuqImwDkOd9iSxvTC8vzh-HrhuohOIjWMrGpTZi2FdzVN4Ll3fb2Iz3s_hj-Lno_c6m_7VcmOHfRLC9sPjSu2q9dbNkKo8Zc2FQmsCBdQi06XGAEJZW2M9380pxoYKiJ51a4EbGl4Ag7lX3hXeTPYRMVifacgdlpg2SYZzDPZQbWvibgtXFsBsIqPd-8i6ucE2eMdaNeWMLsHv-b5s7uWn8hN2nMKHj000Qce5rSbpK58l2LNeWw4IR6wNOqSZfbeerMxq1u0p-ZKIQxP24MltaPjZtqMdD4AzjrP4UCEf7VaLSkSuNVSf6ZmLmE_OYgQuQe7adFdoPg";

// will echo provided payload back as return value, for consistency
byte[] payload = Jose.JWT.DecodeBytes(token, PubKey(), payload: BinaryPayload);
```

### Adding extra headers
jose-jwt allows to pass extra headers when encoding token to overide deafault values<sup>\*</sup>. `extraHeaders:` named param can be used, it accepts `IDictionary<string, object>` type.
jose-jwt is NOT allow to override `alg` and `enc` headers.

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

With JWE JSON (RFC 7516) serialized tokens `JweToken JWE.Headers()` method can be used for same purpose.
It will parse JSON structure into `JweToken` object and pre-populate effective headers (`JweRecipient.JoseHeader` property, see [JWE](#decoding-json-serialized-encrypted-content)) per every recipient in token. But will not perform actual decryption or integrity verification.

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

```C#
// Validate JWE JSON token with dynamic key

// step 1a: parse token, extract public JWK set and keyid for some recipient
var parsed = JWE.Headers(token);
var keysUrl = parsed.UnprotectedHeader["jku"];
var keyId = parsed.Recipients[0].Header["keyid"];

// step 1b: find/retrieve/ensure actual key for decryption
var key = FindKey(keysUrl, keyId);

// step 2: perform actual token validation
var payload = JWE.Decrypt(token, key).Plaintext;
```

### Strict validation
It is possible to use strict validation before decoding a token. This means that you will specify which algorithm and possibly encryption type you are expecting to receive in the header. If the received header doesn't match with the types that you have specified an exception will be thrown and the parsing will be stopped.

Additionally starting v5 `jose-jwt` offering dedicated methods:
- `JWT.Verify()`, `JWT.VerifyBytes()` - same as `JWT.Decode()` but works only with signed tokens, use when you want to explicitly restrict only to signing algs.
- `JWT.Decrypt()`, `JWT.DecryptBytes()` - same as `JWT.Decode()` but works only with encrypted tokens, use when you want to explicitly restrict only to encryption algs.

Both can be additionally combined with strict validation.


Example of how to strictly validate an encrypted token:
```C#
string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg";

byte[] secretKey = new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };

string json = Jose.JWT.Decode(token, secretKey, JweAlgorithm.DIR, JweEncryption.A256GCM);

// starting v5 also applies to dedicated methods
string json = Jose.JWT.Decrypt(token, secretKey, JweAlgorithm.DIR, JweEncryption.A256GCM);
```

Example of how to strictly validate a signed token:
```C#
string token = "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA";

byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };

var publicKey = EccKey.New(x, y);

string json = Jose.JWT.Decode(token, publicKey, JwsAlgorithm.ES256);

// starting v5 also applies to dedicated methods
string json = Jose.JWT.Verify(token, secretKey, JwsAlgorithm.ES256);
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

// Starting v5: reading the binary payload from a token (with signature verification) with explicit method
var decoded = Jose.JWT.VerifyBytes(token, signingKey);

// Starting v5: reading the binary payload from a token (with decryption) with explicit method
var decoded = Jose.JWT.DecryptBytes(token, signingKey);

// Reading the binary payload from a token (without signature verification).
decoded = Jose.JWT.PayloadBytes(token);
```

### Parsing and mapping json to object model directly
jose-jwt library is agnostic about object model used to represent json payload as well as underlying framework used to serialize/parse json objects. Library provides convinient generic methods to work directly with your object model:

```C#
MyDomainObject obj=Jose.JWT.Decode<MyDomainObject>(token,secretKey); //will invoke configured IJsonMapper to perform parsing/mapping of content to MyDomainObject

string data=Jose.JWT.Encode(obj,secrectKey,JwsAlgorithm.HS256); //for object argument configured IJsonMapper will be invoked to serialize object to json string before encoding
```

#### Potential security risk
While deserializing a token, if a field is not provided in token (may due to payload schema changes), the field will remain its default value. This is Newtonsoft.Json's behavior. This hehavior is quite dangerous, which could give attacker chances.

Suppose the payload class is `Payload`.

``` cs
class Payload
{
    public int UserId { get; set; }
}
```

Later the `Payload` class is changed to:

```cs
class Payload
{
    public int Id { get; set; } // UserId -> Id
}
```
Now, if the library deserializes a token issued before the change of `Payload` class, proterty `Id` is not provided in the token and will remain its default value `0`. The payload data will be: `{Id = 0}`.

The user will get someone else's identity (id: 0) .

So developers should always use [nullable data types](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/nullable-value-types) for payload class properties.

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

// as of v5
Jose.JWT.Verify(token, secretKey, settings: settings);
Jose.JWT.Decrypt(token, secretKey, settings: settings);
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

## Customizing library for security
In response to ever increasing attacks on various JWT implementations, `jose-jwt` as of version v4.1 and beyond introduced number of additional security controls to limit potential attack surface on services and projects using the library.

### Deregister algorithm implementations
One can use following methods to deregister any signing, encryption, key management or compression algorithms from runtime suite, that is considered unsafe or simply not expected by service.

 - `JwtSettings.DeregisterJws(JwsAlgorithm alg)` - to remove signing algorithm
 - `JwtSettings.DeregisterJwa(JweAlgorithm alg))` - to remove key management algorithm
 - `JwtSettings.DeregisterJwe(JweEncryption alg)` - to remove signing algorithm
 - `JwtSettings.DeregisterCompression(JweCompression alg)` - to remove signing algorithm

 ```c#
    JWT.DefaultSettings.DeregisterJws(JwsAlgorithm.none)
                       .DeregisterJwe(JweAlgorithm.RSA1_5)
                       .DeregisterJwe(JweAlgorithm.DIR)
                       .DeregisterCompression(JweCompression.DEF);
 ```

### Customizing compression
There were denial-of-service attacks reported on JWT libraries that supports deflate compression by constructing malicious payload that explodes in terms of RAM on decompression. See for details: https://github.com/dvsekhvalnov/jose-jwt/issues/237

As of v5 `jose-jwt` limits decompression buffer to 250Kb to limit memory consumption and additionaly provides a way to adjust the limit according to specific scenarios:

``` cs
    // Override compression alg with new limits (10Kb example)
    Jose.JWT.DefaultSettings.RegisterCompression(JweCompression.DEF, new DeflateCompression(10 * 1024));
```

### Customizing PBKDF2
As it quite easy to abuse `PBES2` family of algorithms via forging header with extra large `p2c` values, `jose-jwt` library introduced iteration count limits in v4.1 to reduce runtime exposure.

By default, `maxIterations` is set according to [OWASP PBKDF2 Recomendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2)

        PBES2-HS256+A128KW: 310000
        PBES2-HS384+A192KW: 250000
        PBES2-HS512+A256KW: 120000

, while `minIterations` kept at `0` for backward compatibility.

If it is desired to implement different limits, it can be achieved via registering `Pbse2HmacShaKeyManagementWithAesKeyWrap` implementation with different parameters:

```c#
    Jose.JWT.DefaultSettings
        // Pick your own min/max limits
        .RegisterJwe(JweAlgorithm.PBES2_HS256_A128KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128), 310000, 310000));
        .RegisterJwe(JweAlgorithm.PBES2_HS384_A192KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(192, new AesKeyWrapManagement(192), 250000, 250000));
        .RegisterJwe(JweAlgorithm.PBES2_HS512_A256KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(256, new AesKeyWrapManagement(256), 120000, 120000));
```

In case you can't upgrade to latest version, but would like to have protections against `PBES2` abuse, it is recommended to stick with [Two-phase validation](#two-phase-validation) precheck before decoding:

```c#
    IDictionary<string, object> headers = Jose.JWT.Headers(token);

    string alg = (string)headers["alg"];
    long p2c = Convert.ToInt32(headers["p2c"]);

    if(alg.StartsWith("PBES2-") && p2c > 310000)
    {
        // potentially can be forged/abused token
    }
    else
    {
        // continue with decoding routine
        Jose.JWT.Decode(token, key);
    }
```

### Confusion attacks and how to nail them
There are number of algorithm confusion attacks reported in general on different JWT libraries in recent years. Typically attacks exploits public keys published on server side (or obtained by other means) via forging bogus JWT tokens signed or encrypted with given public key but with tampered alg header to confuse server validation implementation (hence the attack name). For example take a look at https://github.com/dvsekhvalnov/jose-jwt/issues/236

By nature most of confusion attacks targeting specific usage of libraries rather then libraries itself, as library can't predict in what type of applications and conditions it will be used.

Here are some design practices to consider in your applications to avoid confusion attacks with `jose-jwt`:

1. Clearly separate your signing and encryption keys. **Do not allow** to use signing keys to decrypt tokens and vice versa.

2. When you can, **be explicit** whether you working with signed or encrypted tokens. As of v5 library provides dedicated verification methods: `Verify()` and `Decrypt()`

3. Use [Strict Validation](#strict-validation) and **assert algorithms** explicitly if possible.

4. Always good idea to [deregister](#deregister-algorithm-implementations) algorithms you are **not planning to use** to limit attack surface.

5. For highly dynamic environments consider [two-phase validation](#two-phase-validation) practice to implement more flexible protection measures.


## More examples
Checkout [UnitTests/TestSuite.cs](UnitTests/TestSuite.cs) for more examples.

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

In `startup.cs`, you can add JWT Authorization middleware by passing options to the `services.AddAuthentication` extension method in `void Configure` method.

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

services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options => { options.TokenValidationParameters = tokenValidationParameters; });
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
