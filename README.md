# JSON Web Token (JWT) Implementation for .NET

Minimallistic zero-dependency (almost) library for generating, decoding and ecnryption [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10). Supports wide range 
of [JSON Web Algorithms](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23). JSON parsing agnostic, can plug any desired JSON processing library. 
Extensively tested for compatibility with [jose.4.j](https://bitbucket.org/b_c/jose4j/wiki/Home), [Nimbus-JOSE-JWT](https://bitbucket.org/nimbusds/nimbus-jose-jwt/wiki/Home) and [json-jwt](https://github.com/nov/json-jwt) libraries.

## Foreword
Originally forked from https://github.com/johnsheehan/jwt . Almost re-written from scratch to support JWT encryption capabilities and unified interface for encoding/decoding/encryption.
Moved to separate project in February 2014.

## Supported JWA algorithms

**Signing**
- HMAC signatures with HS256, HS384 and HS512.
- RSASSA-PKCS1-V1_5 signatures with RS256, RS384 and RS512.
- RSASSA-PSS<sup>\*</sup> signatures (probabilistic signature scheme with appendix) with PS256<sup>\*</sup>, PS384<sup>\*</sup> and PS512<sup>\*</sup>.
- NONE (unprotected) plain text algorithm without integrity protection

**Encryption**
- RSAES OAEP encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM<sup>\*</sup>, A192GCM<sup>\*</sup>, A256GCM<sup>\*</sup>
- RSAES-PKCS1-V1_5 encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM<sup>\*</sup>, A192GCM<sup>\*</sup>, A256GCM<sup>\*</sup>
- Direct symmetric key encryption with pre-shared key A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM<sup>\*</sup>, A192GCM<sup>\*</sup> and A256GCM<sup>\*</sup>

##### Notes: <sup>\*</sup> signature and encryption algorithms support provided via CNG BCCrypt API using CLR Security library. Avaliable starting Windows Vista. 

If CLR Security Library can't be found at runtime given algorithms will not be avaliable. But **jose-jwt** can be used without with all other supported algorithms.

## Installation
### NuGet 
...is coming. 

### Manual
Grab source and compile yourself. CLR Security Library can be found in *JWT/lib/* folder or (http://clrsecurity.codeplex.com/)

## Usage
### Creating Plaintext (unprotected) Tokens
	var payload = new Dictionary<string, object>() 
	{
	    { "sub", "mr.x@contoso.com" },
	    { "exp", 1300819380 }
	};

	string token = Jose.JWT.Encode(payload, null, JwsAlgorithm.none);

### Creating signed Tokens
#### HS-* family
HMAC SHA signatures require byte array key of corresponding length

    var payload = new Dictionary<string, object>() 
    {
        { "sub", "mr.x@contoso.com" },
        { "exp", 1300819380 }
    };
	
    var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

    string token=Jose.JWT.Encode(json, secretKey, JwsAlgorithm.HS256);

#### RS-* and PS-* family
RSA signatures require RSACryptoServiceProvider (usually private) key of corresponding length. CSP need to be forced to use Microsoft Enhanced RSA and AES Cryptographic Provider.
Which usually can be done be re-importing RSAParameters. See http://clrsecurity.codeplex.com/discussions/243156 for details.

    var payload = new Dictionary<string, object>() 
    {
        { "sub", "mr.x@contoso.com" },
        { "exp", 1300819380 }
    };
	
    var privateKey=new X509Certificate2("my-key.p12", "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;

    string token=Jose.JWT.Encode(json, privateKey, JwsAlgorithm.RS256);


### Creating encrypted Tokens
#### RSA-* key management family of algorithms
RSA-* key management with AES using SHA or AES GCM encryption requires RSACryptoServiceProvider (usually public) key of corresponding length.

    var payload = new Dictionary<string, object>() 
    {
        { "sub", "mr.x@contoso.com" },
        { "exp", 1300819380 }
    };
	
    var publicKey=new X509Certificate2("my-key.p12", "password").PublicKey.Key as RSACryptoServiceProvider;

    string token = Jose.JWT.Encode(json, publicKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM);


#### DIR direct pre-shared symmetric key family of algorithms 
Direct key management with pre-shared symmetric keys using AES or AES GCM encryption requires byte array key of corresponding length

    var payload = new Dictionary<string, object>() 
    {
        { "sub", "mr.x@contoso.com" },
        { "exp", 1300819380 }
    };
  	
    var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

    string token = Jose.JWT.Encode(json, aes256Key, JweAlgorithm.DIR, JweEncryption.A128CBC_HS256);

#### Optional compressing payload before encrypting
Optional DEFLATE compression is supported

    var payload = new Dictionary<string, object>() 
    {
        { "sub", "mr.x@contoso.com" },
        { "exp", 1300819380 }
    };
	
    var publicKey=new X509Certificate2("my-key.p12", "password").PublicKey.Key as RSACryptoServiceProvider;

    string token = Jose.JWT.Encode(json, publicKey, JweAlgorithm.RSA1_5, JweEncryption.A128CBC_HS256, JweCompression.DEF);



### Verifying and Decoding Tokens
Decoding json web tokens is fully symmetric to creating signed or encrypted tokens:

**HS-** signatures and **DIR** key management algorithm expects byte array key

    string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg";

    byte[] secretKey=new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

    string json = Jose.JWT.Decode(token, secretKey);

**RS-** signatures and **RSA** key management algorthms expects RSACryptoServiceProvider as a key, public/private is asymmetric to encoding:

    string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";

    var privateKey=new X509Certificate2("my-key.p12", "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;

    string json = Jose.JWT.Decode(token,privateKey);

### Parsing and mapping json to object model directly
jose-jwt library is agnostic about object model used to represent json payload as well as underlying framework used to serialize/parse json objects. Library provides convinient generic methods to work directly with your object model:

    MyDomainObject obj=Jose.JWT.Decode<MyDomainObject>(token,secretKey); //will invoke configured IJsonMapper to perform parsing/mapping of content to MyDomainObject 

    string data=Jose.JWT.Encode(obj,secrectKey,JwsAlgorithm.HS256); //for object argument configured IJsonMapper will be invoked to serialize object to json string before encoding


### Customizing json <-> object parsing & mapping
The library provides simple `Jose.IJsonMapper` interface to plug any json processing library or customize default behavior. The only requirement for mapping implementations
is ability to correctly serialize/parse `IDictionary<string,object>` type.

The default supplied `Jose.IJsonMapper` implementation is based on `System.Web.Script.Serialization.JavaScriptSerializer`.

#### Example of Newtonsoft.Json mapper

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

#### Example of ServiceStack mapper

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


