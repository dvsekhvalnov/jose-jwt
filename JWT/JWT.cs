using System;
using System.Collections.Generic;
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
        RSA_OAEP, //RSAES using Optimal Assymetric Encryption Padding, RFC 3447
        DIR, //Direct use of pre-shared symmetric key
        A128KW,
        A192KW,
        A256KW
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
        private static Dictionary<JwsAlgorithm, IJwsAlgorithm> HashAlgorithms;
        private static Dictionary<JweEncryption, IJweAlgorithm> EncAlgorithms;
        private static Dictionary<JweAlgorithm, IKeyManagement> KeyAlgorithms;
        private static Dictionary<JweCompression, ICompression> CompressionAlgorithms;

        private static Dictionary<JweAlgorithm, string> JweAlgorithms = new Dictionary<JweAlgorithm, string>();
        private static Dictionary<JweEncryption, string> JweEncryptionMethods = new Dictionary<JweEncryption, string>();
        private static Dictionary<JweCompression, string> JweCompressionMethods = new Dictionary<JweCompression, string>();
        private static Dictionary<JwsAlgorithm, string> JwsAlgorithms = new Dictionary<JwsAlgorithm, string>();         

        private static IJsonMapper jsMapper;

        public static IJsonMapper JsonMapper
        {
            set { jsMapper = value; }
        }

        static JWT()
        {
            JsonMapper = new JSSerializerMapper();

            HashAlgorithms = new Dictionary<JwsAlgorithm, IJwsAlgorithm>
            {
                {JwsAlgorithm.none, new Plaintext()},
                {JwsAlgorithm.HS256, new HmacUsingSha("SHA256")},
                {JwsAlgorithm.HS384, new HmacUsingSha("SHA384")},
                {JwsAlgorithm.HS512, new HmacUsingSha("SHA512")},

                {JwsAlgorithm.RS256, new RsaUsingSha("SHA256")},
                {JwsAlgorithm.RS384, new RsaUsingSha("SHA384")},
                {JwsAlgorithm.RS512, new RsaUsingSha("SHA512")},

                {JwsAlgorithm.ES256, new EcdsaUsingSha(256)},
                {JwsAlgorithm.ES384, new EcdsaUsingSha(384)},
                {JwsAlgorithm.ES512, new EcdsaUsingSha(521)}
            };

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

            if (ClassAvaliable("Security.Cryptography.RSACng, Security.Cryptography"))
            {
                HashAlgorithms[JwsAlgorithm.PS256] = new RsaPssUsingSha(32);
                HashAlgorithms[JwsAlgorithm.PS384] = new RsaPssUsingSha(48);
                HashAlgorithms[JwsAlgorithm.PS512] = new RsaPssUsingSha(64);

                JwsAlgorithms[JwsAlgorithm.PS256] = "PS256";
                JwsAlgorithms[JwsAlgorithm.PS384] = "PS384";
                JwsAlgorithms[JwsAlgorithm.PS512] = "PS512";
            }

            EncAlgorithms = new Dictionary<JweEncryption, IJweAlgorithm>
            {
                { JweEncryption.A128CBC_HS256, new AesCbcHmac(HashAlgorithms[JwsAlgorithm.HS256], 256) },
                { JweEncryption.A192CBC_HS384, new AesCbcHmac(HashAlgorithms[JwsAlgorithm.HS384], 384) },
                { JweEncryption.A256CBC_HS512, new AesCbcHmac(HashAlgorithms[JwsAlgorithm.HS512], 512) }
            };

            JweEncryptionMethods[JweEncryption.A128CBC_HS256] = "A128CBC-HS256";
            JweEncryptionMethods[JweEncryption.A192CBC_HS384] = "A192CBC-HS384";
            JweEncryptionMethods[JweEncryption.A256CBC_HS512] = "A256CBC-HS512";

            if(ClassAvaliable("Security.Cryptography.AuthenticatedAesCng, Security.Cryptography"))
            {
                EncAlgorithms[JweEncryption.A128GCM] = new AesGcm(128);
                EncAlgorithms[JweEncryption.A192GCM] = new AesGcm(192);
                EncAlgorithms[JweEncryption.A256GCM] = new AesGcm(256);

                JweEncryptionMethods[JweEncryption.A128GCM] = "A128GCM";
                JweEncryptionMethods[JweEncryption.A192GCM] = "A192GCM";
                JweEncryptionMethods[JweEncryption.A256GCM] = "A256GCM";
            }
                                
            KeyAlgorithms = new Dictionary<JweAlgorithm, IKeyManagement>
            {
                { JweAlgorithm.RSA_OAEP, new RsaKeyManagement(true) },
                { JweAlgorithm.RSA1_5, new RsaKeyManagement(false) },
                { JweAlgorithm.DIR, new DirectKeyManagement() },
                { JweAlgorithm.A128KW, new AesKeyWrapManagement(128) },
                { JweAlgorithm.A192KW, new AesKeyWrapManagement(192) },
                { JweAlgorithm.A256KW, new AesKeyWrapManagement(256) }
            };

            JweAlgorithms[JweAlgorithm.RSA1_5] = "RSA1_5";
            JweAlgorithms[JweAlgorithm.RSA_OAEP] = "RSA-OAEP";
            JweAlgorithms[JweAlgorithm.DIR] = "dir";
            JweAlgorithms[JweAlgorithm.A128KW] = "A128KW";
            JweAlgorithms[JweAlgorithm.A192KW] = "A192KW";
            JweAlgorithms[JweAlgorithm.A256KW] = "A256KW";

            CompressionAlgorithms = new Dictionary<JweCompression, ICompression>
            {
                {JweCompression.DEF, new DeflateCompression()}                        
            };

            JweCompressionMethods[JweCompression.DEF] = "DEF";
        }

        /// <summary>
        /// Serialize and encodes object to JWT token and applies requested encryption/compression algorithms.        
        /// </summary>
        /// <param name="payload">json string to encode</param>
        /// <param name="key">key for encryption, suitable for provided JWS algorithm, can be null.</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string Encode(object payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression = null)
        {
            return Encode(jsMapper.Serialize(payload), key, alg, enc);
        }

        /// <summary>
        /// Encodes given json string to JWT token and applies requested encryption/compression algorithms.
        /// Json string to encode will be obtained via configured IJsonMapper implementation.              
        /// </summary>
        /// <param name="payload">json string to encode (not null or whitespace)</param>
        /// <param name="key">key for encryption, suitable for provided JWS algorithm, can be null.</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string Encode(string payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression=null)
        {
            Ensure.IsNotEmpty(payload, "Payload expected to be not empty, whitespace or null.");

            IKeyManagement keys = KeyAlgorithms[alg];
            IJweAlgorithm _enc = EncAlgorithms[enc];

            byte[] cek = keys.NewKey(_enc.KeySize,key);
            byte[] encryptedCek = keys.Wrap(cek, key);

            var jwtHeader = new Dictionary<string,object>{ { "alg" , JweAlgorithms[alg]}, { "enc", JweEncryptionMethods[enc]} };
            
            byte[] plainText = Encoding.UTF8.GetBytes(payload);            

            if (compression.HasValue)
            {
                jwtHeader["zip"] = JweCompressionMethods[compression.Value];
                plainText = CompressionAlgorithms[compression.Value].Compress(plainText);
            }

            byte[] header = Encoding.UTF8.GetBytes(jsMapper.Serialize(jwtHeader));
            byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));
            byte[][] encParts = _enc.Encrypt(aad, plainText, cek);

            return Compact.Serialize(header, encryptedCek, encParts[0], encParts[1], encParts[2]);
        }

        /// <summary>
        /// Serialize and encodes object to JWT token and sign it using given algorithm.  
        /// Json string to encode will be obtained via configured IJsonMapper implementation.      
        /// </summary>
        /// <param name="payload">object to map to json string and encode</param>
        /// <param name="key">key for signing, suitable for provided JWS algorithm, can be null.</param>
        /// <returns>JWT in compact serialization form, digitally signed.</returns>
        public static string Encode(object payload, object key, JwsAlgorithm algorithm)
        {
            return Encode(jsMapper.Serialize(payload), key, algorithm);
        }

        /// <summary>
        /// Encodes given json string to JWT token and sign it using given algorithm.        
        /// </summary>
        /// <param name="payload">json string to encode (not null or whitespace)</param>
        /// <param name="key">key for signing, suitable for provided JWS algorithm, can be null.</param>
        /// <returns>JWT in compact serialization form, digitally signed.</returns>
        public static string Encode(string payload, object key, JwsAlgorithm algorithm)
        {
            Ensure.IsNotEmpty(payload, "Payload expected to be not empty, whitespace or null.");

            var jwtHeader = new Dictionary<string,object> { {"typ", "JWT"}, { "alg", JwsAlgorithms[algorithm]} }; 

            byte[] headerBytes = Encoding.UTF8.GetBytes(jsMapper.Serialize(jwtHeader));
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

            var bytesToSign = Encoding.UTF8.GetBytes(Compact.Serialize(headerBytes, payloadBytes));

            byte[] signature = HashAlgorithms[algorithm].Sign(bytesToSign, key);

            return Compact.Serialize(headerBytes, payloadBytes, signature);
        }

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string is returned untouched (e.g. no parsing or mapping)
        /// </summary>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used, can be null.</param>
        /// <returns>decoded json string</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature,encryption or compression algorithm is not supported</exception>        
        public static string Decode(string token, object key = null)
        {
            Ensure.IsNotEmpty(token, "Incoming token expected to be in compact serialization form, not empty, whitespace or null.");

            byte[][] parts = Compact.Parse(token);

            string json;

            if (parts.Length == 5) //encrypted JWT
            {
                json = Decrypt(parts, key);
            }
            else
            {
                //signed or plain JWT
                byte[] header = parts[0];
                byte[] payload = parts[1];
                byte[] signature = parts[2];

                byte[] securedInput = Encoding.UTF8.GetBytes(Compact.Serialize(header, payload));

                var headerData = jsMapper.Parse<Dictionary<string, object>>(Encoding.UTF8.GetString(header));
                var algorithm = (string)headerData["alg"];

                if (!HashAlgorithms[GetHashAlgorithm(algorithm)].Verify(signature, securedInput, key))
                    throw new IntegrityException("Invalid signature.");

                json = Encoding.UTF8.GetString(payload);
            }

            return json;
        }

        /// <summary>
        /// Decodes JWT token by performining necessary decompression/decryption and signature verification as defined in JWT token header.
        /// Resulting json string will be parsed and mapped to desired type via configured IJsonMapper implementation.
        /// </summary>
        /// <typeparam name="T">Deserid object type after json mapping</typeparam>
        /// <param name="token">JWT token in compact serialization form.</param>
        /// <param name="key">key for decoding suitable for JWT algorithm used, can be null.</param>
        /// <returns>object of provided T, result of decoded json mapping</returns>
        /// <exception cref="IntegrityException">if signature valdation failed</exception>
        /// <exception cref="EncryptionException">if JWT token can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if JWT signature,encryption or compression algorithm is not supported</exception>        
        public static T Decode<T>(string token, object key=null)
        {
            return jsMapper.Parse<T>(Decode(token, key));
        }

        private static string Decrypt(byte[][] parts, object key)
        {
            byte[] header = parts[0];
            byte[] encryptedCek = parts[1];
            byte[] iv = parts[2];
            byte[] cipherText = parts[3];
            byte[] authTag = parts[4];

            var jwtHeader = jsMapper.Parse<Dictionary<string, string>>(Encoding.UTF8.GetString(header));

            IKeyManagement keys = KeyAlgorithms[GetJweAlgorithm(jwtHeader["alg"])];
            IJweAlgorithm enc = EncAlgorithms[GetJweEncryption(jwtHeader["enc"])];

            byte[] cek = keys.Unwrap(encryptedCek, key);
            byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));

            byte[] plainText=enc.Decrypt(aad, cek, iv, cipherText, authTag);

            if (jwtHeader.ContainsKey("zip"))
            {
                plainText = CompressionAlgorithms[GetJweCompression(jwtHeader["zip"])].Decompress(plainText);
            }

            return Encoding.UTF8.GetString(plainText); 
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

        #region Utils

        private static bool ClassAvaliable(string assemblyQualifiedName)
        {
            return Type.GetType(assemblyQualifiedName) != null;
        }

        #endregion
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
