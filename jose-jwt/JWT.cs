using System;
using System.Collections.Generic;
using System.Text;
using Jose.jwe;

namespace Jose
{
    public enum JwsAlgorithm
    {
        none,
        HS256,
        HS384,
        HS512,
        RS256,
        RS384,
        RS512,
        PS256,
        PS384,
        PS512,
        ES256, // ECDSA using P-256 curve and SHA-256 hash 
        ES384, // ECDSA using P-384 curve and SHA-384 hash 
        ES512  // ECDSA using P-521 curve and SHA-512 hash 
    }

    public enum JweAlgorithm
    {
        RSA1_5, //RSAES with PKCS #1 v1.5 padding, RFC 3447
        RSA_OAEP, //RSAES using Optimal Assymetric Encryption Padding, RFC 3447
        RSA_OAEP_256, //RSAES with SHA-256 using Optimal Assymetric Encryption Padding, RFC 3447
        DIR, //Direct use of pre-shared symmetric key
        A128KW, //AES Key Wrap Algorithm using 128 bit keys, RFC 3394
        A192KW, //AES Key Wrap Algorithm using 192 bit keys, RFC 3394
        A256KW,  //AES Key Wrap Algorithm using 256 bit keys, RFC 3394 
        ECDH_ES, //Elliptic Curve Diffie Hellman key agreement
        ECDH_ES_A128KW, //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 128 bit key
        ECDH_ES_A192KW, //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 192 bit key
        ECDH_ES_A256KW, //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 256 bit key
        PBES2_HS256_A128KW, //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 128 bit key        
        PBES2_HS384_A192KW, //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 192 bit key        
        PBES2_HS512_A256KW,  //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 256 bit key        
        A128GCMKW,  //AES GCM Key Wrap Algorithm using 128 bit keys
        A192GCMKW,  //AES GCM Key Wrap Algorithm using 192 bit keys
        A256GCMKW   //AES GCM Key Wrap Algorithm using 256 bit keys
    }

    public enum JweEncryption
    {
        A128CBC_HS256, //AES_128_CBC_HMAC_SHA_256 authenticated encryption using a 256 bit key.
        A192CBC_HS384, //AES_192_CBC_HMAC_SHA_384 authenticated encryption using a 384 bit key.
        A256CBC_HS512, //AES_256_CBC_HMAC_SHA_512 authenticated encryption using a 512 bit key.
        A128GCM,
        A192GCM,
        A256GCM
    }

    public enum JweCompression
    {
        DEF //Deflate compression
    }

    /// <summary>
    /// Provides methods for encoding and decoding JSON Web Tokens.
    /// </summary>
    public static class JWT
    {        
        private static Dictionary<JweAlgorithm, string> JweAlgorithms = new Dictionary<JweAlgorithm, string>();
        private static Dictionary<JweEncryption, string> JweEncryptionMethods = new Dictionary<JweEncryption, string>();
        private static Dictionary<JweCompression, string> JweCompressionMethods = new Dictionary<JweCompression, string>();
        private static Dictionary<JwsAlgorithm, string> JwsAlgorithms = new Dictionary<JwsAlgorithm, string>();

        private static Dictionary<string, JweEncryption> JweEncryptionMethodAliases = new Dictionary<string, JweEncryption>();

        private static JWTSettings defaultSettings;

        /// <summary>
        /// Global default settings for JWT.
        /// </summary>
        public static JWTSettings DefaultSettings
        {
            get { return defaultSettings; }
        }

        [Obsolete("Custom JsonMappers should be set in DefaultSettings")]
        public static IJsonMapper JsonMapper
        {
            set { defaultSettings.JsonMapper = value; }
        }

        static JWT()
        {
            defaultSettings = new JWTSettings();

            JwsAlgorithms[JwsAlgorithm.none] = "none";
            JwsAlgorithms[JwsAlgorithm.HS256] = "HS256";
            JwsAlgorithms[JwsAlgorithm.HS384] = "HS384";
            JwsAlgorithms[JwsAlgorithm.HS512] = "HS512";
            JwsAlgorithms[JwsAlgorithm.RS256] = "RS256";
            JwsAlgorithms[JwsAlgorithm.RS384] = "RS384";
            JwsAlgorithms[JwsAlgorithm.RS512] = "RS512";
            JwsAlgorithms[JwsAlgorithm.ES256] = "ES256";
            JwsAlgorithms[JwsAlgorithm.ES384] = "ES384";
            JwsAlgorithms[JwsAlgorithm.ES512] = "ES512";
            JwsAlgorithms[JwsAlgorithm.PS256] = "PS256";
            JwsAlgorithms[JwsAlgorithm.PS384] = "PS384";
            JwsAlgorithms[JwsAlgorithm.PS512] = "PS512";

            JweEncryptionMethods[JweEncryption.A128CBC_HS256] = "A128CBC-HS256";
            JweEncryptionMethods[JweEncryption.A192CBC_HS384] = "A192CBC-HS384";
            JweEncryptionMethods[JweEncryption.A256CBC_HS512] = "A256CBC-HS512";
            JweEncryptionMethods[JweEncryption.A128GCM] = "A128GCM";
            JweEncryptionMethods[JweEncryption.A192GCM] = "A192GCM";
            JweEncryptionMethods[JweEncryption.A256GCM] = "A256GCM";

            JweAlgorithms[JweAlgorithm.RSA1_5] = "RSA1_5";
            JweAlgorithms[JweAlgorithm.RSA_OAEP] = "RSA-OAEP";
            JweAlgorithms[JweAlgorithm.RSA_OAEP_256] = "RSA-OAEP-256";
            JweAlgorithms[JweAlgorithm.DIR] = "dir";
            JweAlgorithms[JweAlgorithm.A128KW] = "A128KW";
            JweAlgorithms[JweAlgorithm.A192KW] = "A192KW";
            JweAlgorithms[JweAlgorithm.A256KW] = "A256KW";
            JweAlgorithms[JweAlgorithm.ECDH_ES] = "ECDH-ES";
            JweAlgorithms[JweAlgorithm.ECDH_ES_A128KW] = "ECDH-ES+A128KW";
            JweAlgorithms[JweAlgorithm.ECDH_ES_A192KW] = "ECDH-ES+A192KW";
            JweAlgorithms[JweAlgorithm.ECDH_ES_A256KW] = "ECDH-ES+A256KW";
            JweAlgorithms[JweAlgorithm.PBES2_HS256_A128KW] = "PBES2-HS256+A128KW";
            JweAlgorithms[JweAlgorithm.PBES2_HS384_A192KW] = "PBES2-HS384+A192KW";
            JweAlgorithms[JweAlgorithm.PBES2_HS512_A256KW] = "PBES2-HS512+A256KW";
            JweAlgorithms[JweAlgorithm.A128GCMKW] = "A128GCMKW";
            JweAlgorithms[JweAlgorithm.A192GCMKW] = "A192GCMKW";
            JweAlgorithms[JweAlgorithm.A256GCMKW] = "A256GCMKW";

            JweCompressionMethods[JweCompression.DEF] = "DEF";
        }

        /// <summary>
        /// Parses JWT token, extracts and unmarshall headers as IDictionary<string, object>.
        /// This method is NOT performing integrity checking. 
        /// </summary>        
        /// <param name="token">signed JWT token</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>unmarshalled headers</returns>        
        public static IDictionary<string, object> Headers(string token, JWTSettings settings = null)
        {
            return Headers<IDictionary<string, object>>(token, settings);
        }

        /// <summary>
        /// Parses JWT token, extracts and attempst to unmarshall headers to requested type
        /// This method is NOT performing integrity checking. 
        /// </summary>        
        /// <param name="token">signed JWT token</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <typeparam name="T">desired type after unmarshalling</typeparam>
        /// <returns>unmarshalled headers</returns>        
        public static T Headers<T>(string token, JWTSettings settings = null)
        {
            byte[][] parts = Compact.Parse(token);

            return GetSettings(settings).JsonMapper.Parse<T>(Encoding.UTF8.GetString(parts[0]));
        }

        /// <summary>
        /// Parses signed JWT token, extracts and returns payload part as string 
        /// This method is NOT supported for encrypted JWT tokens.
        /// This method is NOT performing integrity checking. 
        /// </summary>        
        /// <param name="token">signed JWT token</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>unmarshalled payload</returns>
        /// <exception cref="JoseException">if encrypted JWT token is provided</exception>        
        public static string Payload(string token, JWTSettings settings = null)
        {
            byte[][] parts = Compact.Parse(token);

            if(parts.Length > 3)
            {
                throw new JoseException(
                    "Getting payload for encrypted tokens is not supported. Please use Jose.JWT.Decode() method instead.");
            }

            return Encoding.UTF8.GetString(parts[1]);
        }

        /// <summary>
        /// Parses signed JWT token, extracts and returns payload part as binary data. 
        /// This method is NOT supported for encrypted JWT tokens.
        /// This method is NOT performing integrity checking. 
        /// </summary>        
        /// <param name="token">signed JWT token</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>unmarshalled payload</returns>
        /// <exception cref="JoseException">if encrypted JWT token is provided</exception>        
        public static byte[] PayloadBytes(string token, JWTSettings settings = null)
        {
            byte[][] parts = Compact.Parse(token);

            if (parts.Length > 3)
            {
                throw new JoseException(
                    "Getting payload for encrypted tokens is not supported. Please use Jose.JWT.Decode() method instead.");
            }

            return parts[1];
        }

        /// <summary>
        /// Parses signed JWT token, extracts payload part and attempts to unmarshall string to requested type with configured json mapper.
        /// This method is NOT supported for encrypted JWT tokens.
        /// This method is NOT performing integrity checking. 
        /// </summary>
        /// <typeparam name="T">desired type after unmarshalling</typeparam>
        /// <param name="token">signed JWT token</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>unmarshalled payload</returns>
        /// <exception cref="JoseException">if encrypted JWT token is provided</exception>
        public static T Payload<T>(string token, JWTSettings settings = null)
        {
            return GetSettings(settings).JsonMapper.Parse<T>(Payload(token));            
        }

        /// <summary>
        /// Serialize and encodes object to JWT token and applies requested encryption/compression algorithms.        
        /// </summary>
        /// <param name="payload">json string to encode</param>
        /// <param name="key">key for encryption, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string Encode(object payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression = null, IDictionary<string, object> extraHeaders = null, JWTSettings settings = null)
        {
            return Encode(GetSettings(settings).JsonMapper.Serialize(payload), key, alg, enc, compression, extraHeaders, settings);
        }

        /// <summary>
        /// Encodes given json string to JWT token and applies requested encryption/compression algorithms.
        /// Json string to encode will be obtained via configured IJsonMapper implementation.              
        /// </summary>
        /// <param name="payload">json string to encode (not null or whitespace)</param>
        /// <param name="key">key for encryption, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string Encode(string payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression = null, IDictionary<string, object> extraHeaders = null, JWTSettings settings = null)
        {
            Ensure.IsNotEmpty(payload, "Payload expected to be not empty, whitespace or null.");

            byte[] plainText = Encoding.UTF8.GetBytes(payload);

            return EncodeBytes(plainText, key, alg, enc, compression, extraHeaders, settings);
        }

        /// <summary>
        /// Encodes given binary data to JWT token and applies requested encryption/compression algorithms.
        /// </summary>
        /// <param name="payload">Binary data to encode (not null)</param>
        /// <param name="key">key for encryption, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string EncodeBytes(byte[] payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression = null, IDictionary<string, object> extraHeaders = null, JWTSettings settings = null)
        {
            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            IKeyManagement keys = GetSettings(settings).KeyAlgorithms[alg];
            IJweAlgorithm _enc = GetSettings(settings).EncAlgorithms[enc];

            IDictionary<string, object> jwtHeader = new Dictionary<string, object> { { "alg", JweAlgorithms[alg] }, { "enc", JweEncryptionMethods[enc] } };

            Dictionaries.Append(jwtHeader, extraHeaders);

            byte[][] contentKeys = keys.WrapNewKey(_enc.KeySize, key, jwtHeader);
            byte[] cek = contentKeys[0];
            byte[] encryptedCek = contentKeys[1];

            if (compression.HasValue)
            {
                jwtHeader["zip"] = JweCompressionMethods[compression.Value];
                payload = GetSettings(settings).CompressionAlgorithms[compression.Value].Compress(payload);
            }

            byte[] header = Encoding.UTF8.GetBytes(GetSettings(settings).JsonMapper.Serialize(jwtHeader));
            byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));
            byte[][] encParts = _enc.Encrypt(aad, payload, cek);

            return Compact.Serialize(header, encryptedCek, encParts[0], encParts[1], encParts[2]);
        }

        /// <summary>
        /// Serialize and encodes object to JWT token and sign it using given algorithm.  
        /// Json string to encode will be obtained via configured IJsonMapper implementation.      
        /// </summary>
        /// <param name="payload">object to map to json string and encode</param>
        /// <param name="key">key for signing, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, digitally signed.</returns>
        public static string Encode(object payload, object key, JwsAlgorithm algorithm, IDictionary<string, object> extraHeaders = null, JWTSettings settings = null)
        {
            return Encode(GetSettings(settings).JsonMapper.Serialize(payload), key, algorithm, extraHeaders, settings);
        }

        /// <summary>
        /// Encodes given json string to JWT token and sign it using given algorithm.        
        /// </summary>
        /// <param name="payload">json string to encode (not null or whitespace)</param>
        /// <param name="key">key for signing, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, digitally signed.</returns>
        public static string Encode(string payload, object key, JwsAlgorithm algorithm, IDictionary<string, object> extraHeaders = null, JWTSettings settings = null)
        {
            Ensure.IsNotEmpty(payload, "Payload expected to be not empty, whitespace or null.");

            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

            return EncodeBytes(payloadBytes, key, algorithm, extraHeaders, settings);
        }

        /// <summary>
        /// Encodes given binary data to JWT token and sign it using given algorithm.        
        /// </summary>
        /// <param name="payload">Binary data to encode (not null)</param>
        /// <param name="key">key for signing, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, digitally signed.</returns>
        public static string EncodeBytes(byte[] payload, object key, JwsAlgorithm algorithm, IDictionary<string, object> extraHeaders = null, JWTSettings settings = null)
        {
            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            if (extraHeaders == null) //allow overload, but keep backward compatible defaults
            {
                extraHeaders = new Dictionary<string, object> { { "typ", "JWT" } };
            }

            var jwtHeader = new Dictionary<string, object> { { "alg", JwsAlgorithms[algorithm] } };

            Dictionaries.Append(jwtHeader, extraHeaders);

            byte[] headerBytes = Encoding.UTF8.GetBytes(GetSettings(settings).JsonMapper.Serialize(jwtHeader));

            var bytesToSign = Encoding.UTF8.GetBytes(Compact.Serialize(headerBytes, payload));

            byte[] signature = GetSettings(settings).HashAlgorithms[algorithm].Sign(bytesToSign, key);

            return Compact.Serialize(headerBytes, payload, signature);
        }

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string is returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="enc">The encryption type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>decoded json string</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static string Decode(string token, object key, JweAlgorithm alg, JweEncryption enc, JWTSettings settings = null)
        {
            return Decode(token, key, null, alg, enc, settings);
        }

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting bytes of the payload are returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="enc">The encryption type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>Decrypted payload as binary data</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static byte[] DecodeBytes(string token, object key, JweAlgorithm alg, JweEncryption enc, JWTSettings settings = null)
		{
			return DecodeBytes(token, key, null, alg, enc, settings);
		}

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string is returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>decoded json string</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static string Decode(string token, object key, JwsAlgorithm alg, JWTSettings settings = null)
        {
            return Decode(token, key, alg, null, null, settings);
        }

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting bytes of the payload are returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>The payload as binary data</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static byte[] DecodeBytes(string token, object key, JwsAlgorithm alg, JWTSettings settings = null)
		{
			return DecodeBytes(token, key, alg, null, null, settings);
		}

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string is returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>decoded json string</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static string Decode(string token, object key = null, JWTSettings settings = null)
        {
            return Decode(token, key, null, null, null, settings);
        }

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting binary payload is returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>The payload as binary data</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static byte[] DecodeBytes(string token, object key = null, JWTSettings settings = null)
		{
			return DecodeBytes(token, key, null, null, null, settings);
		}

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string will be parsed and mapped to desired type via configured IJsonMapper implementation.
        /// </summary>
        /// <typeparam name="T">Deserid object type after json mapping</typeparam>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="enc">The encryption type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>object of provided T, result of decoded json mapping</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static T Decode<T>(string token, object key, JweAlgorithm alg, JweEncryption enc, JWTSettings settings = null)
        {
            return GetSettings(settings).JsonMapper.Parse<T>(Decode(token, key, alg, enc, settings));
        }

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string will be parsed and mapped to desired type via configured IJsonMapper implementation.
        /// </summary>
        /// <typeparam name="T">Deserid object type after json mapping</typeparam>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>object of provided T, result of decoded json mapping</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static T Decode<T>(string token, object key, JwsAlgorithm alg, JWTSettings settings = null)
        {
            return GetSettings(settings).JsonMapper.Parse<T>(Decode(token, key, alg, settings));
        }

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string will be parsed and mapped to desired type via configured IJsonMapper implementation.
        /// </summary>
        /// <typeparam name="T">Deserid object type after json mapping</typeparam>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>object of provided T, result of decoded json mapping</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static T Decode<T>(string token, object key=null, JWTSettings settings = null)
        {
            return GetSettings(settings).JsonMapper.Parse<T>(Decode(token, key, settings));
        }

        private static byte[] DecodeBytes(string token, object key = null, JwsAlgorithm? jwsAlg = null, JweAlgorithm? jweAlg = null, JweEncryption? jweEnc = null, JWTSettings settings = null)
        {
            Ensure.IsNotEmpty(token, "Incoming token expected to be in compact serialization form, not empty, whitespace or null.");

            byte[][] parts = Compact.Parse(token);

            if (parts.Length == 5) //encrypted JWT
            {
                return DecryptBytes(parts, key, jweAlg, jweEnc, settings);
            }
            else
            {
                //signed or plain JWT
                byte[] header = parts[0];
                byte[] payload = parts[1];
                byte[] signature = parts[2];

                byte[] securedInput = Encoding.UTF8.GetBytes(Compact.Serialize(header, payload));

                var headerData = GetSettings(settings).JsonMapper.Parse<Dictionary<string, object>>(Encoding.UTF8.GetString(header));
                var algorithm = (string)headerData["alg"];

                if (jwsAlg != null && (JwsAlgorithm)jwsAlg != GetHashAlgorithm(algorithm))
                    throw new InvalidAlgorithmException("The algorithm type passed to the Decode method did not match the algorithm type in the header.");

                if (!GetSettings(settings).HashAlgorithms[GetHashAlgorithm(algorithm)].Verify(signature, securedInput, key))
                    throw new IntegrityException("Invalid signature.");

                return payload;
            }
        }

        private static string Decode(string token, object key = null, JwsAlgorithm? jwsAlg = null, JweAlgorithm? jweAlg = null, JweEncryption? jweEnc = null, JWTSettings settings = null)
        {
            var payloadBytes = DecodeBytes(token, key, jwsAlg, jweAlg, jweEnc, settings);

            return Encoding.UTF8.GetString(payloadBytes);
        }

        private static byte[] DecryptBytes(byte[][] parts, object key, JweAlgorithm? jweAlg, JweEncryption? jweEnc, JWTSettings settings = null)
        {
            byte[] header = parts[0];
            byte[] encryptedCek = parts[1];
            byte[] iv = parts[2];
            byte[] cipherText = parts[3];
            byte[] authTag = parts[4];

            IDictionary<string, object> jwtHeader = GetSettings(settings).JsonMapper.Parse<Dictionary<string, object>>(Encoding.UTF8.GetString(header));

            JweAlgorithm headerAlg = GetJweAlgorithm((string)jwtHeader["alg"]);
            JweEncryption headerEnc = GetJweEncryption((string)jwtHeader["enc"]);

            IKeyManagement keys = GetSettings(settings).KeyAlgorithms[headerAlg];
            IJweAlgorithm enc = GetSettings(settings).EncAlgorithms[headerEnc];

            if (jweAlg != null && (JweAlgorithm)jweAlg != headerAlg)
                throw new InvalidAlgorithmException("The algorithm type passed to the Decrypt method did not match the algorithm type in the header.");

            if (jweEnc != null && (JweEncryption)jweEnc != headerEnc)
                throw new InvalidAlgorithmException("The encryption type passed to the Decrypt method did not match the encryption type in the header.");

            byte[] cek = keys.Unwrap(encryptedCek, key, enc.KeySize, jwtHeader);
            byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));

            byte[] plainText = enc.Decrypt(aad, cek, iv, cipherText, authTag);

            if (jwtHeader.ContainsKey("zip"))
            {
                plainText = GetSettings(settings).CompressionAlgorithms[GetJweCompression((string)jwtHeader["zip"])].Decompress(plainText);
            }

            return plainText;
        }

        private static JWTSettings GetSettings(JWTSettings settings)
        {
            return settings ?? defaultSettings;
        }

        private static JwsAlgorithm GetHashAlgorithm(string algorithm)
        {
            foreach (var pair in JwsAlgorithms)
            {
                if (pair.Value.Equals(algorithm)) return pair.Key;
            }

            throw new InvalidAlgorithmException(string.Format("Signing algorithm is not supported: {0}",algorithm));
        }

        private static JweAlgorithm GetJweAlgorithm(string algorithm)
        {
            foreach (var pair in JweAlgorithms)
            {
                if (pair.Value.Equals(algorithm)) return pair.Key;
            }

            throw new InvalidAlgorithmException(string.Format("Algorithm is not supported: {0}.", algorithm));
        }

        private static JweEncryption GetJweEncryption(string algorithm)
        {
            foreach (var pair in JweEncryptionMethods)
            {
                if (pair.Value.Equals(algorithm)) return pair.Key;
            }
            JweEncryption enc;
            if (JweEncryptionMethodAliases.TryGetValue(algorithm, out enc))
            {
                return enc;
            }

            throw new InvalidAlgorithmException(string.Format("Encryption algorithm is not supported: {0}.", algorithm));
        }

        private static JweCompression GetJweCompression(string algorithm)
        {
            foreach (var pair in JweCompressionMethods)
            {
                if (pair.Value.Equals(algorithm)) return pair.Key;
            }

            throw new InvalidAlgorithmException(string.Format("Compression algorithm is not supported: {0}.", algorithm));
        }
    }

    public class JoseException : Exception
    {
        public JoseException(string message) : base(message) {}
        public JoseException(string message, Exception innerException) : base(message, innerException){}
    }

    public class IntegrityException : JoseException
    {
        public IntegrityException(string message) : base(message) {}
        public IntegrityException(string message, Exception innerException) : base(message, innerException) { }
    }

    public class EncryptionException : JoseException
    {
        public EncryptionException(string message) : base(message) {}
        public EncryptionException(string message, Exception innerException) : base(message, innerException) { }
    }

    public class InvalidAlgorithmException : JoseException
    {
        public InvalidAlgorithmException(string message) : base(message) { }
        public InvalidAlgorithmException(string message, Exception innerException) : base(message, innerException) { }
    }
}
