using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

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
        RSA_OAEP, //RSAES using Optimal Asymmetric Jwe Padding, RFC 3447
        RSA_OAEP_256, //RSAES with SHA-256 using Optimal Asymmetric Jwe Padding, RFC 3447
        RSA_OAEP_384, //RSAES with SHA-256 using Optimal Asymmetric Jwe Padding, RFC 3447
        RSA_OAEP_512, //RSAES with SHA-256 using Optimal Asymmetric Jwe Padding, RFC 3447
        DIR, //Direct use of pre-shared symmetric key
        A128KW, //AES Key Wrap Algorithm using 128 bit keys, RFC 3394
        A192KW, //AES Key Wrap Algorithm using 192 bit keys, RFC 3394
        A256KW,  //AES Key Wrap Algorithm using 256 bit keys, RFC 3394
        ECDH_ES, //Elliptic Curve Diffie Hellman key agreement
        ECDH_ES_A128KW, //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 128 bit key
        ECDH_ES_A192KW, //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 192 bit key
        ECDH_ES_A256KW, //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 256 bit key
        PBES2_HS256_A128KW, //Password Based Jwe using PBES2 schemes with HMAC-SHA and AES Key Wrap using 128 bit key
        PBES2_HS384_A192KW, //Password Based Jwe using PBES2 schemes with HMAC-SHA and AES Key Wrap using 192 bit key
        PBES2_HS512_A256KW,  //Password Based Jwe using PBES2 schemes with HMAC-SHA and AES Key Wrap using 256 bit key
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
        private static readonly JwtSettings defaultSettings = new JwtSettings();

        /// <summary>
        /// Global default settings for JWT.
        /// </summary>
        public static JwtSettings DefaultSettings
        {
            get { return defaultSettings; }
        }

        [Obsolete("Custom JsonMappers should be set in DefaultSettings")]
        public static IJsonMapper JsonMapper
        {
            set { defaultSettings.RegisterMapper(value); }
        }

        /// <summary>
        /// Parses JWT token, extracts and unmarshal headers as IDictionary<string, object>.
        /// This method is NOT performing integrity checking.
        /// </summary>
        /// <param name="token">signed JWT token</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>unmarshalled headers</returns>
        public static IDictionary<string, object> Headers(string token, JwtSettings settings = null)
        {
            return Headers<IDictionary<string, object>>(token, settings);
        }

        /// <summary>
        /// Parses JWT token, extracts and attempts to unmarshal headers to requested type
        /// This method is NOT performing integrity checking.
        /// </summary>
        /// <param name="token">signed JWT token</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <typeparam name="T">desired type after unmarshalling</typeparam>
        /// <returns>unmarshalled headers</returns>
        public static T Headers<T>(string token, JwtSettings settings = null)
        {
            var parts = Compact.Iterate(token);

            return GetSettings(settings).JsonMapper.Parse<T>(Encoding.UTF8.GetString(parts.Next()));
        }

        /// <summary>
        /// Parses signed JWT token, extracts and returns payload part as string
        /// This method is NOT supported for encrypted JWT tokens.
        /// This method is NOT performing integrity checking.
        /// </summary>
        /// <param name="token">signed JWT token</param>
        /// <returns>unmarshalled payload</returns>
        /// <exception cref="JoseException">if encrypted JWT token is provided</exception>
        public static string Payload(string token, bool b64 = true)
        {
            var bytes = PayloadBytes(token, b64);
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Parses signed JWT token, extracts and returns payload part as binary data.
        /// This method is NOT supported for encrypted JWT tokens.
        /// This method is NOT performing integrity checking.
        /// </summary>
        /// <param name="token">signed JWT token</param>
        /// <returns>unmarshalled payload</returns>
        /// <exception cref="JoseException">if encrypted JWT token is provided</exception>
        public static byte[] PayloadBytes(string token, bool b64 = true)
        {
            var parts = Compact.Iterate(token);

            if (parts.Count < 3)
            {
                throw new JoseException(
                    "The given token doesn't follow JWT format and must contains at least three parts.");
            }

            if (parts.Count > 3)
            {
                throw new JoseException(
                    "Getting payload for encrypted tokens is not supported. Please use Jose.JWT.Decode() method instead.");
            }

            parts.Next(false); //skip header
            return parts.Next(b64);
        }

        /// <summary>
        /// Parses signed JWT token, extracts payload part and attempts to unmarshal string to requested type with configured json mapper.
        /// This method is NOT supported for encrypted JWT tokens.
        /// This method is NOT performing integrity checking.
        /// </summary>
        /// <typeparam name="T">desired type after unmarshalling</typeparam>
        /// <param name="token">signed JWT token</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>unmarshalled payload</returns>
        /// <exception cref="JoseException">if encrypted JWT token is provided</exception>
        public static T Payload<T>(string token, JwtSettings settings = null)
        {
            return GetSettings(settings).JsonMapper.Parse<T>(Payload(token));
        }

        /// <summary>
        /// Serialize and encodes object to JWT token and applies requested encryption/compression algorithms.
        /// </summary>
        /// <param name="payload">json string to encode</param>
        /// <param name="key">key for encryption, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="alg">JWT algorithm to be used.</param>
        /// <param name="enc">encryption algorithm to be used.</param>
        /// <param name="compression">optional compression type to use.</param>
        /// <param name="extraHeaders">optional extra headers to pass along with the payload.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string Encode(object payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression = null, IDictionary<string, object> extraHeaders = null, JwtSettings settings = null)
        {
            return Encode(GetSettings(settings).JsonMapper.Serialize(payload), key, alg, enc, compression, extraHeaders, settings);
        }

        /// <summary>
        /// Encodes given json string to JWT token and applies requested encryption/compression algorithms.
        /// Json string to encode will be obtained via configured IJsonMapper implementation.
        /// </summary>
        /// <param name="payload">json string to encode (not null or whitespace)</param>
        /// <param name="key">key for encryption, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="alg">JWT algorithm to be used.</param>
        /// <param name="enc">encryption algorithm to be used.</param>
        /// <param name="compression">optional compression type to use.</param>
        /// <param name="extraHeaders">optional extra headers to pass along with the payload.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string Encode(string payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression = null, IDictionary<string, object> extraHeaders = null, JwtSettings settings = null)
        {
            byte[] plainText = Encoding.UTF8.GetBytes(payload);

            return EncodeBytes(plainText, key, alg, enc, compression, extraHeaders, settings);
        }

        /// <summary>
        /// Encodes given binary data to JWT token and applies requested encryption/compression algorithms.
        /// </summary>
        /// <param name="payload">Binary data to encode (not null)</param>
        /// <param name="key">key for encryption, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="alg">JWT algorithm to be used.</param>
        /// <param name="enc">encryption algorithm to be used.</param>
        /// <param name="compression">optional compression type to use.</param>
        /// <param name="extraHeaders">optional extra headers to pass along with the payload.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string EncodeBytes(byte[] payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression = null, IDictionary<string, object> extraHeaders = null, JwtSettings settings = null)
        {
            return JWE.EncryptBytes(payload, new JweRecipient[] { new JweRecipient(alg, key) }, enc, aad: null, SerializationMode.Compact, compression, extraHeaders, null, settings);
        }

        /// <summary>
        /// Serialize and encodes object to JWT token and sign it using given algorithm.
        /// Json string to encode will be obtained via configured IJsonMapper implementation.
        /// </summary>
        /// <param name="payload">object to map to json string and encode</param>
        /// <param name="key">key for signing, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="algorithm">JWT algorithm to be used.</param>
        /// <param name="extraHeaders">optional extra headers to pass along with the payload.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <param name="options">additional encoding options</param>
        /// <returns>JWT in compact serialization form, digitally signed.</returns>
        public static string Encode(object payload, object key, JwsAlgorithm algorithm, IDictionary<string, object> extraHeaders = null, JwtSettings settings = null, JwtOptions options = null)
        {
            return Encode(GetSettings(settings).JsonMapper.Serialize(payload), key, algorithm, extraHeaders, settings, options);
        }

        /// <summary>
        /// Encodes given json string to JWT token and sign it using given algorithm.
        /// </summary>
        /// <param name="payload">json string to encode (not null or whitespace)</param>
        /// <param name="key">key for signing, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="algorithm">JWT algorithm to be used.</param>
        /// <param name="extraHeaders">optional extra headers to pass along with the payload.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <param name="options">additional encoding options</param>
        /// <returns>JWT in compact serialization form, digitally signed.</returns>
        public static string Encode(string payload, object key, JwsAlgorithm algorithm, IDictionary<string, object> extraHeaders = null, JwtSettings settings = null, JwtOptions options = null)
        {
            return EncodeStream(new MemoryStream(Encoding.UTF8.GetBytes(payload)), key, algorithm, extraHeaders, settings, options);
        }

        /// <summary>
        /// Encodes given binary data to JWT token and sign it using given algorithm.
        /// </summary>
        /// <param name="payload">Binary data to encode (not null)</param>
        /// <param name="key">key for signing, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="algorithm">JWT algorithm to be used.</param>
        /// <param name="extraHeaders">optional extra headers to pass along with the payload.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <param name="options">additional encoding options</param>
        /// <returns>JWT in compact serialization form, digitally signed.</returns>
        public static string EncodeBytes(byte[] payload, object key, JwsAlgorithm algorithm, IDictionary<string, object> extraHeaders = null, JwtSettings settings = null, JwtOptions options = null)
        {
            return EncodeStream(new MemoryStream(payload), key, algorithm, extraHeaders, settings, options);
        }

        /// <summary>
        /// Encodes given stream to JWT token and sign it using given algorithm.
        /// </summary>
        /// <param name="payload">Stream to encode (not null)</param>
        /// <param name="key">key for signing, suitable for provided JWS algorithm, can be null.</param>
        /// <param name="algorithm">JWT algorithm to be used.</param>
        /// <param name="extraHeaders">optional extra headers to pass along with the payload.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <param name="options">additional encoding options</param>
        /// <returns>JWT in compact serialization form, digitally signed.</returns>
        public static string EncodeStream(Stream payload, object key, JwsAlgorithm algorithm, IDictionary<string, object> extraHeaders = null, JwtSettings settings = null, JwtOptions options = null)
        {
             if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            var jwtSettings = GetSettings(settings);
            var jwtOptions = options ?? JwtOptions.Default;

            var jwtHeader = new Dictionary<string, object> { { "alg", jwtSettings.JwsHeaderValue(algorithm) } };

            if (extraHeaders == null) //allow overload, but keep backward compatible defaults
            {
                extraHeaders = new Dictionary<string, object> { { "typ", "JWT" } };
            }

            if (!jwtOptions.EncodePayload)
            {
                jwtHeader["b64"] = false;
                jwtHeader["crit"] = Collections.Union(new[] { "b64" }, Dictionaries.Get<object>(extraHeaders, "crit"));
            }

            Dictionaries.Append(jwtHeader, extraHeaders);

            byte[] headerBytes = Encoding.UTF8.GetBytes(jwtSettings.JsonMapper.Serialize(jwtHeader));

            var jwsAlgorithm = jwtSettings.Jws(algorithm);
            if (jwsAlgorithm == null)
            {
                throw new JoseException(string.Format("Unsupported JWS algorithm requested: {0}", algorithm));
            }

            // Ensure we have a seekable, rewindable payload stream for signing & serialization.
            if (!payload.CanSeek)
                throw new NotImplementedException("Non-seekable streams are not supported for JWT signing.");

            long originalPosition = payload.Position;
            if (payload.Position != 0) payload.Position = 0; // sign from start for deterministic output

            // Sign over secured input without disposing caller's stream.
            using (var signingInput = securedInput(headerBytes, payload, jwtOptions.EncodePayload))
            {
                byte[] signature = jwsAlgorithm.Sign(signingInput, key);

                // Rewind for serialization (if seekable)
                if (payload.CanSeek) payload.Position = 0;

                // Detached payload: empty stream placeholder; otherwise reuse payload (wrapped to avoid disposal).
                Stream payloadForToken = jwtOptions.DetachPayload
                    ? new MemoryStream()
                    : payload; // payload kept open via ConcatenatedStream keepOpen

                using (var tokenStream = Compact.Serialize(headerBytes, payloadForToken, jwtOptions.EncodePayload, signature))
                using (var reader = new StreamReader(tokenStream, Encoding.UTF8))
                {
                    // Restore caller payload position if it was seekable and we changed it.
                    if (payload.CanSeek)
                        payload.Position = originalPosition;
                    return reader.ReadToEnd();
                }
            }
        }

        /// <summary>
        /// Decodes JWT token by performing necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string is returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="enc">The encryption type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>decoded json string</returns>
        /// <exception cref="IntegrityException">if signature validation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static string Decode(string token, object key, JweAlgorithm alg, JweEncryption enc, JwtSettings settings = null)
        {
            return Decode(token, key, null, alg, enc, settings);
        }

        /// <summary>
        /// Decodes JWT token by performing necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting bytes of the payload are returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="enc">The encryption type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>Decrypted payload as binary data</returns>
        /// <exception cref="IntegrityException">if signature validation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static byte[] DecodeBytes(string token, object key, JweAlgorithm alg, JweEncryption enc, JwtSettings settings = null)
        {
            return DecodeBytes(Compact.Iterate(token), key, null, alg, enc, settings);
        }

        /// <summary>
        /// Decodes JWT token by performing necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string is returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <param name="payload">optional detached payload</param>
        /// <returns>decoded json string</returns>
        /// <exception cref="IntegrityException">if signature validation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static string Decode(string token, object key, JwsAlgorithm alg, JwtSettings settings = null, string payload = null)
        {
            return Decode(token, key, alg, null, null, settings, payload);
        }

        /// <summary>
        /// Decodes JWT token by performing necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting bytes of the payload are returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <param name="payload">optional detached payload</param>
        /// <returns>The payload as binary data</returns>
        /// <exception cref="IntegrityException">if signature validation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static byte[] DecodeBytes(string token, object key, JwsAlgorithm alg, JwtSettings settings = null, byte[] payload = null)
        {
            return DecodeBytes(Compact.Iterate(token), key, alg, null, null, settings, payload);
        }

        /// <summary>
        /// Decodes JWT token by performing necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string is returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <param name="payload">optional detached payload</param>
        /// <returns>decoded json string</returns>
        /// <exception cref="IntegrityException">if signature validation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static string Decode(string token, object key = null, JwtSettings settings = null, string payload = null)
        {
            return Decode(token, key, null, null, null, settings, payload);
        }

        /// <summary>
        /// Decodes JWT token by performing necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting binary payload is returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <param name="payload">optional detached payload</param>
        /// <returns>The payload as binary data</returns>
        /// <exception cref="IntegrityException">if signature validation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static byte[] DecodeBytes(string token, object key = null, JwtSettings settings = null, byte[] payload = null)
        {
            return DecodeBytes(Compact.Iterate(token), key, null, null, null, settings, payload);
        }

        /// <summary>
        /// Decodes JWT token by performing necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string will be parsed and mapped to desired type via configured IJsonMapper implementation.
        /// </summary>
        /// <typeparam name="T">Deserid object type after json mapping</typeparam>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="enc">The encryption type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>object of provided T, result of decoded json mapping</returns>
        /// <exception cref="IntegrityException">if signature validation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static T Decode<T>(string token, object key, JweAlgorithm alg, JweEncryption enc, JwtSettings settings = null)
        {
            return GetSettings(settings).JsonMapper.Parse<T>(Decode(token, key, alg, enc, settings));
        }

        /// <summary>
        /// Decodes JWT token by performing necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string will be parsed and mapped to desired type via configured IJsonMapper implementation.
        /// </summary>
        /// <typeparam name="T">Deserid object type after json mapping</typeparam>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used.</param>
        /// <param name="alg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>object of provided T, result of decoded json mapping</returns>
        /// <exception cref="IntegrityException">if signature validation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static T Decode<T>(string token, object key, JwsAlgorithm alg, JwtSettings settings = null)
        {
            return GetSettings(settings).JsonMapper.Parse<T>(Decode(token, key, alg, settings));
        }

        /// <summary>
        /// Decodes JWT token by performing necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string will be parsed and mapped to desired type via configured IJsonMapper implementation.
        /// </summary>
        /// <typeparam name="T">Deserid object type after json mapping</typeparam>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used, can be null.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>object of provided T, result of decoded json mapping</returns>
        /// <exception cref="IntegrityException">if signature validation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature, encryption or compression algorithm is not supported</exception>
        public static T Decode<T>(string token, object key = null, JwtSettings settings = null)
        {
            return GetSettings(settings).JsonMapper.Parse<T>(Decode(token, key, settings));
        }

        public static string Verify(string token, object key, JwsAlgorithm? alg = null, JwtSettings settings = null, string payload = null)
        {
            var detached = payload != null ? Encoding.UTF8.GetBytes(payload) : null;

            return Encoding.UTF8.GetString(VerifyBytes(token, key, alg, settings, detached));
        }

        public static byte[] VerifyBytes(string token, object key, JwsAlgorithm? alg = null, JwtSettings settings = null, byte[] payload = null)
        {
            var parts = Compact.Iterate(token);

            if (parts.Count != 3)
            {
                throw new JoseException("Unexpected number of parts in signed token: " + parts.Count);
            }

            return DecodeBytes(parts, key, alg, null, null, settings, payload);
        }

        public static string Decrypt(string token, object key, JweAlgorithm? alg = null, JweEncryption? enc = null, JwtSettings settings = null)
        {
            return Encoding.UTF8.GetString(DecryptBytes(token, key, alg, enc, settings));
        }

        public static byte[] DecryptBytes(string token, object key, JweAlgorithm? alg = null, JweEncryption? enc = null, JwtSettings settings = null)
        {
            var parts = Compact.Iterate(token);

            if (parts.Count != 5)
            {
                throw new JoseException("Unexpected number of parts in encrypted token: " + parts.Count);
            }

            return DecodeBytes(parts, key, null, alg, enc, settings);
        }


        private static byte[] DecodeBytes(Compact.Iterator parts, object key = null, JwsAlgorithm? expectedJwsAlg = null, JweAlgorithm? expectedJweAlg = null, JweEncryption? expectedJweEnc = null, JwtSettings settings = null, byte[] payload = null)
        {
            Ensure.IsNotEmpty(parts.Token, "Incoming token expected to be in compact serialization form, not empty, whitespace or null.");

            if (parts.Count == 5) //encrypted JWT
            {
                if (expectedJwsAlg != null)
                {
                    throw new InvalidAlgorithmException("Encrypted tokens can't assert signing algorithm type.");
                }

                return JWE.Decrypt(parts.Token, key, expectedJweAlg, expectedJweEnc, settings).PlaintextBytes;
            }
            else if (parts.Count == 3) // signed JWT
            {
                if (expectedJweAlg != null || expectedJweEnc != null)
                {
                    throw new InvalidAlgorithmException("Signed tokens can't assert encryption type.");
                }

                //signed or plain JWT
                var jwtSettings = GetSettings(settings);

                byte[] header = parts.Next();

                var headerData = jwtSettings.JsonMapper.Parse<IDictionary<string, object>>(Encoding.UTF8.GetString(header));

                bool b64 = true;

                object value;
                if (headerData.TryGetValue("b64", out value))
                {
                    b64 = (bool)value;
                }

                byte[] contentPayload = parts.Next(b64);
                byte[] signature = parts.Next();

                var effectivePayload = payload ?? contentPayload;

                var algorithm = (string)headerData["alg"];
                var jwsAlgorithm = jwtSettings.JwsAlgorithmFromHeader(algorithm);
                if (expectedJwsAlg != null && expectedJwsAlg != jwsAlgorithm)
                {
                    throw new InvalidAlgorithmException(
                        "The algorithm type passed to the Decode method did not match the algorithm type in the header.");
                }

                var jwsAlgorithmImpl = jwtSettings.Jws(jwsAlgorithm);

                if (jwsAlgorithmImpl == null)
                {
                    throw new JoseException(string.Format("Unsupported JWS algorithm requested: {0}", algorithm));
                }

                if (!jwsAlgorithmImpl.Verify(signature, securedInput(header, new MemoryStream(effectivePayload), b64), key))
                {
                    throw new IntegrityException("Invalid signature.");
                }

                return effectivePayload;
            }

            throw new JoseException("Expected compact serialized token with 3 or 5 parts, but got: " + parts.Count);
        }

        private static string Decode(string token, object key = null, JwsAlgorithm? jwsAlg = null, JweAlgorithm? jweAlg = null, JweEncryption? jweEnc = null, JwtSettings settings = null, string payload = null)
        {
            var detached = payload != null ? Encoding.UTF8.GetBytes(payload) : null;

            var payloadBytes = DecodeBytes(Compact.Iterate(token), key, jwsAlg, jweAlg, jweEnc, settings, detached);

            return Encoding.UTF8.GetString(payloadBytes);
        }

        private static JwtSettings GetSettings(JwtSettings settings)
        {
            return settings ?? defaultSettings;
        }

        private static Stream securedInput(byte[] header, Stream payload, bool b64)
        {
            // Keep payload stream open (caller owns it)
            return Compact.Serialize(header, payload, b64);
        }
    }

    public class JoseException : Exception
    {
        public JoseException(string message) : base(message) { }
        public JoseException(string message, Exception innerException) : base(message, innerException) { }
    }

    public class IntegrityException : JoseException
    {
        public IntegrityException(string message) : base(message) { }
        public IntegrityException(string message, Exception innerException) : base(message, innerException) { }
    }

    public class EncryptionException : JoseException
    {
        public EncryptionException(string message) : base(message) { }
        public EncryptionException(string message, Exception innerException) : base(message, innerException) { }
    }

    public class InvalidAlgorithmException : JoseException
    {
        public InvalidAlgorithmException(string message) : base(message) { }
        public InvalidAlgorithmException(string message, Exception innerException) : base(message, innerException) { }
    }

    public class CapacityExceededException : JoseException
    {
        public CapacityExceededException(string message) : base(message) { }
        public CapacityExceededException(string message, Exception innerException) : base(message, innerException) { }
    }
}
