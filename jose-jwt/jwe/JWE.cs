
namespace Jose
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;       

    public enum SerializationMode
    {
        Compact,
        Json,
    };

    /// <summary>
    /// Provides methods for encrypting and decrypting using JSON Web Encryption (JWE).
    /// </summary>
    public class JWE
    {
        /// <summary>
        /// Encrypts given plaintext using JWE and applies requested encryption/compression algorithms.
        /// </summary>
        /// <param name="plaintext">Binary data to encrypt (not null)</param>
        /// <param name="recipients">The details of who to encrypt the plaintext (or rather the CEK) to.</param>
        /// <param name="enc">encryption algorithm to be used to encrypt the plaintext.</param>
        /// <param name="aad">additional authentication data (SerializationMode.Json only)</param>
        /// <param name="mode">serialization mode to use. Note only one recipient can be specified for compact and flattened json serialization.</param>
        /// <param name="compression">optional compression type to use.</param>
        /// <param name="extraProtectedHeaders">optional extra headers to put in the protected header.</param>
        /// <param name="unprotectedHeaders">optional unprotected headers</param> 
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string Encrypt(string plaintext, IEnumerable<JweRecipient> recipients, JweEncryption enc, byte[] aad = null, SerializationMode mode = SerializationMode.Json, JweCompression? compression = null, IDictionary<string, object> extraProtectedHeaders = null, IDictionary<string, object> unprotectedHeaders = null, JwtSettings settings = null)
        {
            return EncryptBytes(Encoding.UTF8.GetBytes(plaintext), recipients, enc, aad, mode, compression, extraProtectedHeaders, unprotectedHeaders, settings);
        }

        /// <summary>
        /// Encrypts given binary plaintext using JWE and applies requested encryption/compression algorithms.
        /// </summary>
        /// <param name="plaintext">Binary data to encrypt (not null)</param>
        /// <param name="recipients">The details of who to encrypt the plaintext (or rather the CEK) to.</param>
        /// <param name="enc">encryption algorithm to be used to encrypt the plaintext.</param>
        /// <param name="aad">additional authentication data (SerializationMode.Json only)</param>
        /// <param name="mode">serialization mode to use. Note only one recipient can be specified for compact and flattened json serialization.</param>
        /// <param name="compression">optional compression type to use.</param>
        /// <param name="extraProtectedHeaders">optional extra headers to put in the protected header.</param>
        /// <param name="unprotectedHeaders">optional unprotected headers</param> 
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string EncryptBytes(byte[] plaintext, IEnumerable<JweRecipient> recipients, JweEncryption enc, byte[] aad = null, SerializationMode mode = SerializationMode.Json, JweCompression? compression = null, IDictionary<string, object> extraProtectedHeaders = null, IDictionary<string, object> unprotectedHeaders = null, JwtSettings settings = null)
        {
            if (plaintext == null)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            settings = GetSettings(settings);
            IJweAlgorithm _enc = settings.Jwe(enc);

            if (_enc == null)
            {
                throw new JoseException(string.Format("Unsupported JWE enc requested: {0}", enc));
            }

            IDictionary<string, object> joseProtectedHeader = Dictionaries.MergeHeaders(
                new Dictionary<string, object> { { "enc", settings.JweHeaderValue(enc) } },
                extraProtectedHeaders);

            byte[] cek = null;

            var recipientsOut = new List<JweRecipient>();
            foreach (var recipient in recipients)
            {
                IKeyManagement keys = settings.Jwa(recipient.Alg);

                if (keys == null)
                {
                    throw new JoseException(string.Format("Unsupported JWE alg requested: {0}", recipient.Alg));
                }

                // joseHeader - is merge of headers
                // - key management will read from (e.g. enc,apv,apu - ECDH-ES)
                // - key management will write to (e.g. iv, tag - AesGcmKW)
                IDictionary<string, object> joseHeader = Dictionaries.MergeHeaders(
                    joseProtectedHeader,
                    new Dictionary<string, object> { { "alg", settings.JwaHeaderValue(recipient.Alg) } },
                    recipient.Header,
                    unprotectedHeaders
                    );

                byte[] encryptedCek;
                if(cek == null)
                {
                    byte[][] contentKeys = keys.WrapNewKey(_enc.KeySize, recipient.Key, joseHeader);
                    cek = contentKeys[0];
                    encryptedCek = contentKeys[1];
                }
                else
                {
                    encryptedCek = keys.WrapKey(cek, recipient.Key, joseHeader);
                }

                // For the per-receipient header we want the headers from the result of IKeyManagements key wrapping but without the
                // shared headers
                IDictionary<string, object> recipientHeader = joseHeader
                    .Where(
                        kvp => !joseProtectedHeader.ContainsKey(kvp.Key) && 
                        (unprotectedHeaders==null || !unprotectedHeaders.ContainsKey(kvp.Key))
                    )                                                                       
                   .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

                recipientsOut.Add(new JweRecipient(encryptedCek, recipientHeader));
            }

            if (compression.HasValue)
            {
                joseProtectedHeader["zip"] = settings.CompressionHeader(compression.Value);
                plaintext = settings.Compression(compression.Value).Compress(plaintext);
            }

            switch (mode)
            {
                case SerializationMode.Compact:
                    {
                        if (recipientsOut.Count != 1)
                        {
                            throw new JoseException("Only one recipient is supported by the JWE Compact Serialization.");
                        }

                        if (aad != null)
                        {
                            throw new JoseException("JWE AAD value is not valid for JWE Compact Serialization.");
                        }

                        joseProtectedHeader = Dictionaries.MergeHeaders(recipientsOut[0].Header, joseProtectedHeader);

                        byte[] header = Encoding.UTF8.GetBytes(settings.JsonMapper.Serialize(joseProtectedHeader));
                        aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));
                        byte[][] encParts = _enc.Encrypt(aad, plaintext, cek);

                        return new JweToken(
                                        header, 
                                        null, 
                                        recipientsOut, 
                                        null, 
                                        encParts[0], 
                                        encParts[1], 
                                        encParts[2], 
                                        mode)
                                   .AsString();                        
                    }

                case SerializationMode.Json:
                    {                        
                        var protectedHeaderBytes = Encoding.UTF8.GetBytes(settings.JsonMapper.Serialize(joseProtectedHeader));                        
                        byte[] asciiEncodedProtectedHeader = Encoding.ASCII.GetBytes(Base64Url.Encode(protectedHeaderBytes));
                        byte[][] encParts = _enc.Encrypt(Aad(protectedHeaderBytes, aad), plaintext, cek);                       

                        return new JweToken(
                                    protectedHeaderBytes, 
                                    unprotectedHeaders, 
                                    recipientsOut, 
                                    aad, 
                                    encParts[0], 
                                    encParts[1], 
                                    encParts[2], 
                                    mode)
                                .AsString(settings.JsonMapper);                        
                    }

                default:
                    throw new JoseException($"Unsupported serializtion mode: {mode}.");
            }
        }        

        /// <summary>
        /// Decypts a JWE by performing necessary decompression/decryption and authenticated decryption as defined in RFC7516.
        /// </summary>
        /// <param name="jwe">JWE to decrypt.</param>
        /// <param name="key">key for decoding suitable for JWE algorithm used to encrypt the CEK.</param>
        /// <param name="expectedJweAlg">The algorithm type that we expect to receive in the header.</param>
        /// <param name="expectedJweEnc">The encryption type that we expect to receive in the header.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>Decrypted JweToken object</returns>
        /// <exception cref="IntegrityException">if AEAD operation validation failed</exception>
        /// <exception cref="EncryptionException">if JWE can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if encryption or compression algorithm is not supported</exception>
        public static JweToken Decrypt(string jwe, object key, JweAlgorithm? expectedJweAlg = null, JweEncryption? expectedJweEnc = null, JwtSettings settings = null)
        {
            Ensure.IsNotEmpty(jwe, "Incoming jwe expected to be in a valid serialization form, not empty, whitespace or null.");

            settings = GetSettings(settings);
            
            JweToken token = Headers(jwe);

            if(token.ProtectedHeaderBytes==null && token.Encoding == SerializationMode.Compact)
            {
                throw new JoseException(string.Format("Protected header was missing but required with compact encoding."));
            }            

            var exceptions = new List<Exception>();

            foreach (var recipient in token.Recipients)
            {
                var headerAlg = settings.JwaAlgorithmFromHeader((string)recipient.JoseHeader["alg"]);
                var encryptedCek = recipient.EncryptedCek;

                // skip recipient if asked to do strict validation
                if(expectedJweAlg != null && expectedJweAlg != headerAlg)
                {
                    continue;
                }

                IKeyManagement keys = settings.Jwa(headerAlg);

                if (keys == null)
                {
                    throw new JoseException(string.Format("Unsupported JWA algorithm requested: {0}", headerAlg));
                }

                try
                {
                    JweEncryption headerEnc = settings.JweAlgorithmFromHeader((string)recipient.JoseHeader["enc"]);
                    IJweAlgorithm enc = settings.Jwe(headerEnc);

                    if (enc == null)
                    {
                        throw new JoseException(string.Format("Unsupported JWE algorithm requested: {0}", headerEnc));
                    }

                    if (expectedJweEnc != null && expectedJweEnc != headerEnc)
                    {
                        throw new InvalidAlgorithmException("The encryption type passed to the Decrypt method did not match the encryption type in the header.");
                    }

                    byte[] cek = keys.Unwrap(recipient.EncryptedCek, key, enc.KeySize, recipient.JoseHeader);
                    byte[] plaintext = enc.Decrypt(Aad(token.ProtectedHeaderBytes, token.Aad), cek, token.Iv, token.Ciphertext, token.AuthTag);

                    if (recipient.JoseHeader.TryGetValue("zip", out var compressionAlg))
                    {
                        var compression = settings.Compression((string)compressionAlg);

                        plaintext = compression.Decompress(plaintext);
                    }
                    
                    token.PlaintextBytes = plaintext;
                    token.Recipient = recipient;

                    return token;
                }
                catch (ArgumentException ex)
                {
                    exceptions.Add(ex);
                }
                catch (JoseException ex)
                {
                    exceptions.Add(ex);
                }
            }

            // nobody was eligable for decryption
            if(exceptions.Count == 0)
            {
                throw new InvalidAlgorithmException("The algorithm type passed to the Decrypt method did not match the algorithm type in the header.");
            }

            // decryption failed
            if (exceptions.Select(e => new KeyValuePair<Type, String>(e.GetType(), e.Message)).Distinct().Count() == 1)
            {
                // throw the first
                throw exceptions[0];
            }
            else
            {
                throw new JoseException($"No recipients able to decrypt.", new AggregateException(exceptions));
            }
        }

        /// <summary>
        /// Parses JWE token, extracts and unmarshal protected+unprotcted+per recipient headers
        /// This method is NOT performing integrity checking and actual decryption 
        /// </summary>
        /// <param name="jwe">Serialized JWE string to decrypt.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>List of Jose headers. For Compact and Flattened this will be length 1 and contain just the protected header. 
        ///  For General Json this will be the Jose headers (merge of protected, unprotected and per-recipient).</returns>
        /// <exception cref="IntegrityException">if AEAD operation validation failed</exception>
        /// <exception cref="EncryptionException">if JWE can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if encryption or compression algorithm is not supported</exception>
        public static JweToken Headers(string jwe, JwtSettings settings = null)
        {
            settings = GetSettings(settings);
            
            var token = JweToken.FromString(jwe, settings.JsonMapper);           

            var protectedHeader = settings.JsonMapper.Parse<Dictionary<string, object>>(
                Encoding.UTF8.GetString(token.ProtectedHeaderBytes));

            foreach(var recipient in token.Recipients)
            {
                try
                {
                    recipient.JoseHeader = Dictionaries.MergeHeaders(protectedHeader, token.UnprotectedHeader, recipient.Header);
                }
                catch (ArgumentException)
                {
                    throw new JoseException("Invalid JWE data, duplicate header keys found between protected, unprotected and recipient headers");
                }            
            }

            return token;
        }                

        private static JwtSettings GetSettings(JwtSettings settings)
        {
            return settings ?? JWT.DefaultSettings;
        }

        private static byte[] Aad(byte[] protectedHeader, byte[] aad = null)
        {
            return aad == null ?
                Encoding.ASCII.GetBytes(Base64Url.Encode(protectedHeader)) :
                Encoding.ASCII.GetBytes(string.Concat(Base64Url.Encode(protectedHeader), ".", Base64Url.Encode(aad)));
        }

    }
}