namespace Jose
{
    using System;
    using System.Collections;
    using System.Collections.Generic;

    /// <summary>
    /// JWE token object representation.
    /// Supports serizalization / deserialization from as compact, flattened json or general json.
    /// </summary>
    public class JweToken
    {
        /// <summary>
        /// Serialize token according to serialization mode
        /// </summary>
        public string AsString(IJsonMapper mapper = null)
        {
            if(Encoding == SerializationMode.Compact)
            {
                return Compact.Serialize(ProtectedHeaderBytes, Recipients[0].EncryptedCek, Iv, Ciphertext, AuthTag);
            }

            var json = new Dictionary<string, object>()
            {
                { "ciphertext",  Base64Url.Encode(Ciphertext) },
                { "protected",  Base64Url.Encode(ProtectedHeaderBytes) },
                { "iv",  Base64Url.Encode(Iv) },
                { "tag",  Base64Url.Encode(AuthTag) }
            };

            if (Aad != null)
            {
                json["aad"] = Base64Url.Encode(Aad);
            }

            if (UnprotectedHeader != null)
            {
                json["unprotected"] = UnprotectedHeader;
            }


            if (Recipients.Count == 1)
            {
                json["header"] = Recipients[0].Header;
                json["encrypted_key"] = Base64Url.Encode(Recipients[0].EncryptedCek);
            }
            else
            {
                var recipientList = new List<object>();


                foreach (var recipient in Recipients)
                {
                    recipientList.Add(
                        new Dictionary<string, object> {
                            { "header", recipient.Header },
                            { "encrypted_key", Base64Url.Encode(recipient.EncryptedCek) }
                        }
                    );
                }
            
                json["recipients"] = recipientList;
            }

            return mapper.Serialize(json);
        }

        /// <summary>
        /// Parse serialized token
        /// </summary>
        public static JweToken FromString(string token, IJsonMapper jsonMapper=null)
        {
            bool isJsonEncoded = token.Trim().StartsWith("{", StringComparison.Ordinal);

            return isJsonEncoded 
                ? ParseJson(jsonMapper.Parse<IDictionary<string, object>>(token)) 
                : ParseCompact(token);
        }

        /// <summary>
        /// Protected header serialized value
        /// </summary>
        public byte[] ProtectedHeaderBytes { get; }

        /// <summary>
        /// Unprotected header
        /// </summary>
        public IDictionary<string, object> UnprotectedHeader { get; }

        /// <summary>
        /// List of recipient information token is encoded for
        /// </summary>
        public List<JweRecipient> Recipients { get; }

        /// <summary>
        /// Effective recipient that have been used to decode token. Null if no decode happened successfully.
        /// </summary>
        public JweRecipient Recipient { get; internal set; }

        /// <summary>
        /// Additional Authentication Data (JSON only)
        /// </summary>
        public byte[] Aad { get; }

        /// <summary>
        /// Init vector
        /// </summary>
        public byte[] Iv { get; }

        /// <summary>
        /// Ciphertext (encrypted plaintext)
        /// </summary>
        public byte[] Ciphertext { get; }

        /// <summary>
        /// Plaintext (decrypted ciphertext). Null if no decode happened successfully.
        /// </summary>
        public byte[] PlaintextBytes { get; internal set; }

        /// <summary>
        /// Convinience helper to get Plaintext as string
        /// </summary>
        public string Plaintext { 
            get 
            {
                var blob = PlaintextBytes;

                return blob == null ? null : System.Text.Encoding.UTF8.GetString(PlaintextBytes);
            } 
        }

        /// <summary>
        /// Authentication tag
        /// </summary>
        public byte[] AuthTag { get; }

        /// <summary>
        /// Token serialization: Json | Compact
        /// </summary>
        public SerializationMode Encoding { get; }

        public JweToken(
            byte[] protectedHeaderBytes,
            IDictionary<string, object> unprotectedHeader,
            List<JweRecipient> recipients,
            byte[] aad,
            byte[] iv,
            byte[] ciphertext,
            byte[] authTag,
            SerializationMode encoding)
        {
            ProtectedHeaderBytes = protectedHeaderBytes;
            UnprotectedHeader = unprotectedHeader;
            Recipients = recipients;
            Aad = aad;
            Iv = iv;
            Ciphertext = ciphertext;
            AuthTag = authTag;
            Encoding = encoding;
        }

        private static JweToken ParseCompact(string jwe)
        {
            var parts = Compact.Iterate(jwe);

            var protectedHeaderBytes = parts.Next();
            byte[] encryptedCek = parts.Next();
            var iv = parts.Next();
            var ciphertext = parts.Next();
            var authTag = parts.Next();

            var recipients = new List<JweRecipient>();
            recipients.Add(new JweRecipient(encryptedCek, new Dictionary<string, object>()));

            return new JweToken(
                protectedHeaderBytes: protectedHeaderBytes,
                unprotectedHeader: null,
                aad: null,
                recipients: recipients,
                iv: iv,
                ciphertext: ciphertext,
                authTag: authTag,
                encoding: SerializationMode.Compact);
        }

        private static JweToken ParseJson(IDictionary<string, object> json)
        {
            var recipients = new List<JweRecipient>();

           IEnumerable _recipients = Dictionaries.Get<IEnumerable>(json, "recipients");

            if (_recipients != null)
            {
                foreach (IDictionary<string, object> recipient in _recipients)
                {
                    byte[] encryptedCek = Base64Url.Decode(Dictionaries.Get<string>(recipient, "encrypted_key"));
                    recipients.Add(new JweRecipient(encryptedCek, Dictionaries.Get<IDictionary<string, object>>(recipient, "header")));
                }
            }
            else if (recipients.Count == 0)
            {
                byte[] encryptedCek = Base64Url.Decode(Dictionaries.Get<string>(json, "encrypted_key"));
                recipients.Add(new JweRecipient(encryptedCek, Dictionaries.Get<IDictionary<string, object>>(json, "header")));
            }

            var _protected = Dictionaries.Get<string>(json, "protected");
            var _aad = Dictionaries.Get<string>(json, "aad");

            return new JweToken(
                protectedHeaderBytes: _protected == null ? new byte[0] : Base64Url.Decode(_protected),
                unprotectedHeader: Dictionaries.Get<IDictionary<string, object>>(json, "unprotected"),
                aad: _aad == null ? null : Base64Url.Decode(_aad),
                recipients: recipients,
                iv: Base64Url.Decode(Dictionaries.Get<string>(json, "iv")),
                ciphertext: Base64Url.Decode(Dictionaries.Get<string>(json, "ciphertext")),
                authTag: Base64Url.Decode(Dictionaries.Get<string>(json, "tag")),
                encoding: SerializationMode.Json);
        }
    }
}