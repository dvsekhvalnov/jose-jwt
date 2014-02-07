# JSON Web Token (JWT) Implementation for .NET

This library supports generating, decoding and ecnryption [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10).

## Foreword
Originally forked from https://github.com/johnsheehan/jwt . Almost re-written from scratch to support JWT encryption capabilities and unified interface for encoding/decoding/encryption.
Moved to separate project in February 2014.

## Supported JWA algorithms

**Signing**
- HMAC signatures with HS256, HS384 and HS512.
- RSASSA-PKCS1-V1_5 signatures with RS256, RS384 and RS512.
- NONE (unprotected) plain text algorithm without integrity protection

**Encryption**
- RSAES OAEP encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
- RSAES-PKCS1-V1_5 encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512


## Installation
The easiest way to install is via NuGet.  See [here](https://nuget.org/packages/JWT).  Else, you can download and compile it yourself.

## Usage
### Creating Plaintext (unprotected) Tokens
	var payload = new Dictionary<string, object>() 
	{
	    { "sub", "mr.x@contoso.com" },
	    { "exp", 1300819380 }
	};

	string token = JWT.JsonWebToken.Encode(payload, JwtHashAlgorithm.none);
	Console.Out.WriteLine(token);

### Creating signed Tokens
    var payload = new Dictionary<string, object>() 
	{
        { "sub", "mr.x@contoso.com" },
        { "exp", 1300819380 }
    };
	
    var secretKey = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
    string token = JWT.JsonWebToken.Encode(payload, secretKey, JwtHashAlgorithm.HS256);
    Console.Out.WriteLine(token);

Output will be:

    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s



### Creating encrypted Tokens

TODO


### Verifying and Decoding Tokens

    var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
    var secretKey = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
    try
    {
        string jsonPayload = JWT.JsonWebToken.Decode(token, secretKey);
        Console.Out.WriteLine(jsonPayload);
    }
    catch (JWT.SignatureVerificationException e)
    {
        Console.Out.WriteLine("Invalid token!");
    }

Output will be:

    {"claim1":0,"claim2":"claim2-value"}

You can also deserialize the JSON payload directly to a .Net object with DecodeToObject:

    var payload = JWT.JsonWebToken.DecodeToObject(token, secretKey) as IDictionary<string, object>;
    Console.Out.WriteLine(payload["claim2"]);

which will output:
    
    claim2-value
