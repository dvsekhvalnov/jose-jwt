#if NETSTANDARD
namespace Jose.jwe
{
    using Newtonsoft.Json;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    public class JweRecipient
    {
        /// <summary
        /// A recipient for a Jwe
        /// </summary
        /// <param name="alg">algorithm to be used to encrypt the CEK (Content Encryption Key).</param>
        /// <param name="key">key for encrypting CEK (Content Encryption Key). Cannot be null.</param>
        public JweRecipient(JweAlgorithm alg, object key, IDictionary<string, object> perRecipientHeaders = null)
        {
            this.Alg = alg;
            this.Key = key ?? throw new ArgumentNullException(nameof(key));
            this.PerRecipientHeaders = perRecipientHeaders;
        }

        public JweAlgorithm Alg { get; set; }

        public object Key { get; set; }

        internal IDictionary<string, object> PerRecipientHeaders { get; }
    }

    public enum SerializationMode
    {
        smCompact,
        smGeneralJson,
        smFlattenedJson,
    };

    /// <summary>
    /// Provides methods for encrypting and decrypting using JSON Web Encryption (JWE).
    /// </summary>
    public class Jwe
    {
        /// <summary>
        /// Encrypts given plaintext using JWE and applies requested encryption/compression algorithms.
        /// </summary>
        /// <param name="plaintext">Binary data to encrypt (not null)</param>
        /// <param name="recipients">The details of who to encrypt the plaintext (or rather the CEK) to.</param>
        /// <param name="enc">encryption algorithm to be used to encrypt the plaintext.</param>
        /// <param name="mode">serialization mode to use. Note only one recipient can be specified for compact and flattened json serialization.</param>
        /// <param name="compression">optional compression type to use.</param>
        /// <param name="extraHeaders">optional extra headers to put in the JoseProtectedHeader.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>JWT in compact serialization form, encrypted and/or compressed.</returns>
        public static string Encrypt(byte[] plaintext, IEnumerable<JweRecipient> recipients, JweEncryption enc, SerializationMode mode = SerializationMode.smCompact, JweCompression? compression = null, IDictionary<string, object> extraHeaders = null, JwtSettings settings = null)
        {
            if (plaintext == null)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            JwtSettings jwtSettings = GetSettings(settings);
            IJweAlgorithm _enc = jwtSettings.Jwe(enc);

            if (_enc == null)
            {
                throw new JoseException(string.Format("Unsupported JWE enc requested: {0}", enc));
            }

            IDictionary<string, object> joseProtectedHeader = MergeHeaders(
                new Dictionary<string, object> { { "enc", jwtSettings.JweHeaderValue(enc) } },
                extraHeaders);

            byte[] cek = null;

            var recipientsOut = new List<(byte[] EncryptedKey, IDictionary<string, object> Header)>();
            foreach (var recipient in recipients)
            {
                IKeyManagement keys = jwtSettings.Jwa(recipient.Alg);

                if (keys == null)
                {
                    throw new JoseException(string.Format("Unsupported JWE alg requested: {0}", recipient.Alg));
                }

                // joseHeader - is merge of headers
                // - key management will read from (e.g. enc,apv,apu - ECDH-ES)
                // - key management will write to (e.g. iv, tag - AesGcmKW)
                IDictionary<string, object> joseHeader = MergeHeaders(
                    joseProtectedHeader,
                    new Dictionary<string, object> { { "alg", jwtSettings.JwaHeaderValue(recipient.Alg) } },
                    recipient.PerRecipientHeaders);

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

                // For the per-receipient header we want the headers from the result of IKeyManagements key wrapping.. but without the
                // protected headers that were merged in
                IDictionary<string, object> recipientHeader = joseHeader.Except(joseProtectedHeader).ToDictionary(x => x.Key, v => v.Value);

                recipientsOut.Add((EncryptedKey: encryptedCek, Header: recipientHeader));
            }

            if (compression.HasValue)
            {
                joseProtectedHeader["zip"] = jwtSettings.CompressionHeader(compression.Value);
                plaintext = jwtSettings.Compression(compression.Value).Compress(plaintext);
            }

            switch (mode)
            {
                case SerializationMode.smCompact:
                    {
                        if (recipientsOut.Count != 1)
                        {
                            throw new JoseException("Only one recipient is supported by the JWE Compact Serialization.");
                        }

                        joseProtectedHeader = MergeHeaders(recipientsOut[0].Header, joseProtectedHeader);

                        byte[] header = Encoding.UTF8.GetBytes(jwtSettings.JsonMapper.Serialize(joseProtectedHeader));
                        byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));
                        byte[][] encParts = _enc.Encrypt(aad, plaintext, cek);

                        return Compact.Serialize(header, recipientsOut[0].EncryptedKey, encParts[0], encParts[1], encParts[2]);
                    }

                case SerializationMode.smFlattenedJson:
                    {
                        if (recipientsOut.Count != 1)
                        {
                            throw new JoseException("Only one recipient is supported by the Flattened JWE JSON Serialization.");
                        }

                        var protectedHeaderBytes = Encoding.UTF8.GetBytes(jwtSettings.JsonMapper.Serialize(joseProtectedHeader));
                        byte[] aad = Encoding.ASCII.GetBytes(Base64Url.Encode(protectedHeaderBytes));
                        byte[][] encParts = _enc.Encrypt(aad, plaintext, cek);

                        return jwtSettings.JsonMapper.Serialize(new
                        {
                            @protected = Base64Url.Encode(protectedHeaderBytes),
                            header = recipientsOut.Select(r => r.Header).First(),
                            encrypted_key = recipientsOut.Select(r => Base64Url.Encode(r.EncryptedKey)).First(),
                            iv = Base64Url.Encode(encParts[0]),
                            ciphertext = Base64Url.Encode(encParts[1]),
                            tag = Base64Url.Encode(encParts[2]),
                        });
                    }

                case SerializationMode.smGeneralJson:
                    {
                        var protectedHeaderBytes = Encoding.UTF8.GetBytes(jwtSettings.JsonMapper.Serialize(joseProtectedHeader));
                        byte[] aad = Encoding.ASCII.GetBytes(Base64Url.Encode(protectedHeaderBytes));
                        byte[][] encParts = _enc.Encrypt(aad, plaintext, cek);

                        return jwtSettings.JsonMapper.Serialize(new
                        {
                            @protected = Base64Url.Encode(protectedHeaderBytes),
                            recipients = recipientsOut.Select(r => new
                            {
                                header = r.Header,
                                encrypted_key = Base64Url.Encode(r.EncryptedKey),
                            }),
                            iv = Base64Url.Encode(encParts[0]),
                            ciphertext = Base64Url.Encode(encParts[1]),
                            tag = Base64Url.Encode(encParts[2]),
                        });
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
        /// <param name="mode">serialization mode to use. Note only one recipient can be specified for compact and flattened json serialization.</param>
        /// <param name="settings">optional settings to override global DefaultSettings</param>
        /// <returns>Decrypted plaintext as binary data</returns>
        /// <exception cref="IntegrityException">if AEAD operation validation failed</exception>
        /// <exception cref="EncryptionException">if JWE can't be decrypted</exception>
        /// <exception cref="InvalidAlgorithmException">if encryption or compression algorithm is not supported</exception>
        public static (byte[] Plaintext, IDictionary<string, object> JoseHeaders) Decrypt(string jwe, object key, JweAlgorithm? expectedJweAlg = null, JweEncryption? expectedJweEnc = null, SerializationMode mode = SerializationMode.smCompact, JwtSettings settings = null)
        {
            Ensure.IsNotEmpty(jwe, "Incoming jwe expected to be in a valid serialization form, not empty, whitespace or null.");

            JwtSettings jwtSettings = GetSettings(settings);

            IDictionary<string, object> protectedHeader;
            IDictionary<string, object> unprotectedHeader = null;
            byte[] protectedHeaderBytes;
            byte[] iv;
            byte[] ciphertext;
            byte[] authTag;

            var recipients = new List<(byte[] EncryptedCek, IDictionary<string, object> Header)>();

            switch (mode)
            {
                case SerializationMode.smCompact:
                    {
                        var parts = Compact.Iterate(jwe);

                        protectedHeaderBytes = parts.Next();
                        byte[] encryptedCek = parts.Next();
                        iv = parts.Next();
                        ciphertext = parts.Next();
                        authTag = parts.Next();

                        protectedHeader = jwtSettings.JsonMapper.Parse<Dictionary<string, object>>(Encoding.UTF8.GetString(protectedHeaderBytes));
                        recipients.Add((EncryptedCek: encryptedCek, Header: new Dictionary<string, object>()));
                        break;
                    }

                case SerializationMode.smFlattenedJson:
                    {
                        // TODO - do we want the entire object deserialized using the custom JsonMapper?
                        var jweJson = jwtSettings.JsonMapper.Parse<FlattenedJweJson>(jwe);

                        protectedHeaderBytes = jweJson.ProtectedHeaderBytes();
                        iv = jweJson.IvBytes();
                        ciphertext = jweJson.CiphertextBytes();
                        authTag = jweJson.TagBytes();

                        byte[] encryptedCek = jweJson.EncryptedKeyBytes();
                        recipients.Add((EncryptedCek: encryptedCek, Header: jweJson.Header));

                        protectedHeader = jwtSettings.JsonMapper.Parse<Dictionary<string, object>>(Encoding.UTF8.GetString(protectedHeaderBytes));
                        unprotectedHeader = jweJson.Unprotected;

                        break;
                    }

                case SerializationMode.smGeneralJson:
                    {
                        // TODO - do we want the entire object deserialized using the custom JsonMapper?
                        var jweJson = jwtSettings.JsonMapper.Parse<GeneralJweJson>(jwe);

                        protectedHeaderBytes = jweJson.ProtectedHeaderBytes();
                        iv = jweJson.IvBytes();
                        ciphertext = jweJson.CiphertextBytes();
                        authTag = jweJson.TagBytes();

                        foreach (var recipient in jweJson.Recipients)
                        {
                            byte[] encryptedCek = recipient.EncryptedKeyBytes();
                            recipients.Add((EncryptedCek: encryptedCek, Header: recipient.Header));
                        }

                        protectedHeader = jwtSettings.JsonMapper.Parse<Dictionary<string, object>>(Encoding.UTF8.GetString(protectedHeaderBytes));
                        unprotectedHeader = jweJson.Unprotected;

                        break;
                    }

                default:
                    throw new JoseException($"Unsupported serializtion mode: {mode}");
            }

            JweEncryption headerEnc = jwtSettings.JweAlgorithmFromHeader((string)protectedHeader["enc"]);
            IJweAlgorithm enc = jwtSettings.Jwe(headerEnc);

            if (enc == null)
            {
                throw new JoseException(string.Format("Unsupported JWE algorithm requested: {0}", headerEnc));
            }

            if (expectedJweEnc != null && expectedJweEnc != headerEnc)
            {
                throw new InvalidAlgorithmException("The encryption type passed to the Decrypt method did not match the encryption type in the header.");
            }

            var algMatchingRecipients = recipients.Select(r =>
            {
                var joseHeader = MergeHeaders(protectedHeader, unprotectedHeader, r.Header);
                return new
                {
                    JoseHeader = joseHeader,
                    HeaderAlg = jwtSettings.JwaAlgorithmFromHeader((string)joseHeader["alg"]),
                    EncryptedCek = r.EncryptedCek,
                };
            })
                .Where(r => (expectedJweAlg == null || expectedJweAlg == r.HeaderAlg));

            if (!algMatchingRecipients.Any())
            {
                throw new InvalidAlgorithmException("The algorithm type passed to the Decrypt method did not match the algorithm type in the header.");
            }

            var exceptions = new List<Exception>();

            foreach (var recipient in algMatchingRecipients)
            {
                IKeyManagement keys = jwtSettings.Jwa(recipient.HeaderAlg);

                if (keys == null)
                {
                    throw new JoseException(string.Format("Unsupported JWA algorithm requested: {0}", recipient.HeaderAlg));
                }

                try
                {
                    byte[] cek = keys.Unwrap(recipient.EncryptedCek, key, enc.KeySize, protectedHeader);
                    byte[] aad = Encoding.ASCII.GetBytes(Base64Url.Encode(protectedHeaderBytes));

                    byte[] plaintext = enc.Decrypt(aad, cek, iv, ciphertext, authTag);

                    if (recipient.JoseHeader.TryGetValue("zip", out var compressionAlg))
                    {
                        var compression = jwtSettings.Compression((string)compressionAlg);

                        plaintext = compression.Decompress(plaintext);
                    }
                    return (Plaintext: plaintext, JoseHeaders: recipient.JoseHeader);
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

            if (exceptions.Select(e => (e.GetType(), e.Message)).Distinct().Count() == 1)
            {
                // throw the first
                throw exceptions[0];
            }
            else
            {
                throw new JoseException($"No recipients able to decrypt.", new AggregateException(exceptions));
            }
        }

        private static IDictionary<string, object> MergeHeaders(params IDictionary<string, object>[] dicts)
        {
            return dicts
                .Where(dict => dict != null)
                .SelectMany(x => x)
                .ToDictionary(k => k.Key, k => k.Value);
        }

        private static JwtSettings GetSettings(JwtSettings settings)
        {
            return settings ?? JWT.DefaultSettings;
        }
    }
}
#endif //NETSTANDARD2_1