using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace Json
{
    public enum JwsAlgorithm
    {
        none,
        HS256,
        HS384,
        HS512,
        RS256,
        RS384,
        RS512
    }

    public enum JweAlgorithm
    {
        RSA1_5, //RSAES with PKCS #1 v1.5 padding, RFC 3447
        RSA_OAEP, //RSAES using Optimal Assymetric Encryption Padding, RFC 3447
        DIR //Direct use of pre-shared symmetric key
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

    /// <summary>
    /// Provides methods for encoding and decoding JSON Web Tokens.
    /// </summary>
    public static class JWT
    {        
        private static Dictionary<JwsAlgorithm, IJwsAlgorithm> HashAlgorithms;
        private static Dictionary<JweEncryption, IJweAlgorithm> EncAlgorithms;
        private static Dictionary<JweAlgorithm, IKeyManagement> KeyAlgorithms;

        private static Dictionary<JweAlgorithm, string> JweAlgorithms = new Dictionary<JweAlgorithm, string>();
        private static Dictionary<JweEncryption, string> JweEncryptionMethods = new Dictionary<JweEncryption, string>();         

        private static JavaScriptSerializer js = new JavaScriptSerializer();

        static JWT()
        {
            HashAlgorithms = new Dictionary<JwsAlgorithm, IJwsAlgorithm>
            {
                { JwsAlgorithm.none, new Plaintext()},
                { JwsAlgorithm.HS256, new HmacUsingSha("SHA256") },   
                { JwsAlgorithm.HS384, new HmacUsingSha("SHA384") },   
                { JwsAlgorithm.HS512, new HmacUsingSha("SHA512") },   

                { JwsAlgorithm.RS256, new RsaUsingSha("SHA256") },
                { JwsAlgorithm.RS384, new RsaUsingSha("SHA384") },
                { JwsAlgorithm.RS512, new RsaUsingSha("SHA512") }
            };

            EncAlgorithms = new Dictionary<JweEncryption, IJweAlgorithm>
            {
                { JweEncryption.A128CBC_HS256, new AesCbcHmac(HashAlgorithms[JwsAlgorithm.HS256], 256) },
                { JweEncryption.A192CBC_HS384, new AesCbcHmac(HashAlgorithms[JwsAlgorithm.HS384], 384) },
                { JweEncryption.A256CBC_HS512, new AesCbcHmac(HashAlgorithms[JwsAlgorithm.HS512], 512) },
                { JweEncryption.A128GCM, new AesGcm(128) },
                { JweEncryption.A192GCM, new AesGcm(192) },
                { JweEncryption.A256GCM, new AesGcm(256) }
            };
                                
            KeyAlgorithms = new Dictionary<JweAlgorithm, IKeyManagement>
            {
                { JweAlgorithm.RSA_OAEP, new RsaKeyManagement(true) },
                { JweAlgorithm.RSA1_5, new RsaKeyManagement(false) },
                { JweAlgorithm.DIR, new DirectKeyManagement() }
            };

            JweAlgorithms[JweAlgorithm.RSA1_5] = "RSA1_5";
            JweAlgorithms[JweAlgorithm.RSA_OAEP] = "RSA-OAEP";
            JweAlgorithms[JweAlgorithm.DIR] = "dir";

            JweEncryptionMethods[JweEncryption.A128CBC_HS256] = "A128CBC-HS256";
            JweEncryptionMethods[JweEncryption.A192CBC_HS384] = "A192CBC-HS384";
            JweEncryptionMethods[JweEncryption.A256CBC_HS512] = "A256CBC-HS512";
            JweEncryptionMethods[JweEncryption.A128GCM] = "A128GCM";
            JweEncryptionMethods[JweEncryption.A192GCM] = "A192GCM";
            JweEncryptionMethods[JweEncryption.A256GCM] = "A256GCM";
        }

        /// <summary>
        /// Given a JWT, decode it, verify signature via HS* and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key bytes that were used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>A string containing the JSON payload.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        public static object Decode(string token, byte[] key, bool parseJson = false)
        {
            return Decode(token, (object)key, parseJson);
        }

        /// <summary>
        /// Given a JWT, decode it, verify signature and return the JSON payload (optionally parse it).
        /// </summary>
        /// <param name="token">The JWT token in compact serialization form</param>
        /// <param name="key">The public part of key that was used to sign the JWT. (Used with RS-* family)</param>
        /// <param name="parseJson">Whether to parse payload and returd Dictionary or return unparsed json as string (default is true).</param>
        /// <returns>A string containing the JSON payload or IDictionary<string,object> depending on parseJson values.</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        public static object Decode(string token, AsymmetricAlgorithm key, bool parseJson = false)
        {
            return Decode(token, (object)key, parseJson);
        }

        /// <summary>
        /// Given a JWT, decode it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="parseJson">Whether to parse json payload (default is false).</param>
        /// <returns>A string containing the JSON payload or IDictionary<string,object> depending on parse option</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
        public static object Decode(string token, string key, bool parseJson = false)
        {
            return Decode(token, Encoding.UTF8.GetBytes(key), parseJson);
        }

        public static object Decode(string token, bool parseJson = false)
        {
            return Decode(token, (object)null, parseJson);
        }

        public static string Encode(object payload, object key, JweAlgorithm alg, JweEncryption enc)
        {
            return Encode(js.Serialize(payload), key, alg, enc);
        }

        public static string Encode(string payload, object key, JweAlgorithm alg, JweEncryption enc)
        {
            IKeyManagement keys = KeyAlgorithms[alg];
            IJweAlgorithm _enc = EncAlgorithms[enc];

            byte[] cek = keys.NewKey(_enc.KeySize,key);
            byte[] encryptedCek = keys.Wrap(cek, key);

            var jwtHeader = new { alg = JweAlgorithms[alg], enc = JweEncryptionMethods[enc] };

            byte[] header = Encoding.UTF8.GetBytes(js.Serialize(jwtHeader));
            byte[] plainText = Encoding.UTF8.GetBytes(payload);
            byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));

            byte[][] encParts = _enc.Encrypt(aad, plainText, cek);

            return Compact.Serialize(header, encryptedCek, encParts[0], encParts[1], encParts[2]);
        }

        public static string Encode(object payload, object key, JwsAlgorithm algorithm)
        {
            return Encode(js.Serialize(payload), key, algorithm);
        }

        public static string Encode(string payload, object key, JwsAlgorithm algorithm)
        {
            var header = new { typ = "JWT", alg = algorithm.ToString() };

            byte[] headerBytes = Encoding.UTF8.GetBytes(js.Serialize(header));
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

            var bytesToSign = Encoding.UTF8.GetBytes(Compact.Serialize(headerBytes, payloadBytes));

            byte[] signature = HashAlgorithms[algorithm].Sign(bytesToSign, key);

            return Compact.Serialize(headerBytes, payloadBytes, signature);
        }

        private static object Decode(string token, object key, bool parseJson = false)
        {
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

                var headerData = js.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(header));
                var algorithm = (string)headerData["alg"];

                if (!HashAlgorithms[GetHashAlgorithm(algorithm)].Verify(signature, securedInput, key))
                    throw new SignatureVerificationException("Invalid signature.");

                json = Encoding.UTF8.GetString(payload);
            }

            return parseJson ? (object) js.Deserialize<Dictionary<string,object>>(json) : json;
        }

        private static string Decrypt(byte[][] parts, object key)
        {
            byte[] header = parts[0];
            byte[] encryptedCek = parts[1];
            byte[] iv = parts[2];
            byte[] cipherText = parts[3];
            byte[] authTag = parts[4];

            var jwtHeader = js.Deserialize<Dictionary<string, string>>(Encoding.UTF8.GetString(header));

            IKeyManagement keys = KeyAlgorithms[GetJweAlgorithm(jwtHeader["alg"])];
            IJweAlgorithm enc = EncAlgorithms[GetJweEncryption(jwtHeader["enc"])];

            byte[] cek = keys.Unwrap(encryptedCek, key);
            byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));

            byte[] plainText=enc.Decrypt(aad, cek, iv, cipherText, authTag);
            
            return Encoding.UTF8.GetString(plainText); //todo: apply de-compression if needed & parse
        }
        
        private static JwsAlgorithm GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case "none": return JwsAlgorithm.none;
                case "HS256": return JwsAlgorithm.HS256;
                case "HS384": return JwsAlgorithm.HS384;
                case "HS512": return JwsAlgorithm.HS512;
                case "RS256": return JwsAlgorithm.RS256;
                case "RS384": return JwsAlgorithm.RS384;
                case "RS512": return JwsAlgorithm.RS512;

                default: throw new SignatureVerificationException("Signing algorithm is not supported.");
            }
        }

        private static JweAlgorithm GetJweAlgorithm(string algorithm)
        {
            foreach (var pair in JweAlgorithms)
            {
                if (pair.Value.Equals(algorithm)) return pair.Key;
            }

            throw new SignatureVerificationException("Algorithm is not supported.");
        }

        private static JweEncryption GetJweEncryption(string algorithm)
        {
            foreach (var pair in JweEncryptionMethods)
            {
                if (pair.Value.Equals(algorithm)) return pair.Key;
            }

            throw new SignatureVerificationException("Encryption is not supported.");
        }

    }

    public class SignatureVerificationException : Exception
    {
        public SignatureVerificationException(string message) : base(message) {}
    }

    public class DecryptionException : Exception
    {
        public DecryptionException(string message) : base(message) {}
    }
}
