namespace Jose
{
    using System;
    using System.Collections;
    using System.Collections.Generic;

    /// <summary>
    /// Internal class used to represent the data withing a JWE
    /// Note - could have come in as compant, flattened json or general json.
    /// </summary>
    public class JweToken
    {
        public string AsString(IJsonMapper mapper=null)
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


        public static JweToken FromString(string token, IJsonMapper jsonMapper=null)
        {
            bool isJsonEncoded = token.Trim().StartsWith("{", StringComparison.Ordinal);

            return isJsonEncoded 
                ? ParseJson(jsonMapper.Parse<Dictionary<string, object>>(token)) 
                : ParseCompact(token);
        }

        public byte[] ProtectedHeaderBytes { get; }
        public IDictionary<string, object> UnprotectedHeader { get; }
        public List<(byte[] EncryptedCek, IDictionary<string, object> Header)> Recipients { get; }
        public byte[] Aad { get; }
        public byte[] Iv { get; }
        public byte[] Ciphertext { get; }
        public byte[] AuthTag { get; }
        public SerializationMode Encoding { get; }

        public JweToken(
            byte[] protectedHeaderBytes,
            IDictionary<string, object> unprotectedHeader,
            List<(byte[] EncryptedCek, IDictionary<string, object> Header)> recipients,
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

            var recipients = new List<(byte[] EncryptedCek, IDictionary<string, object> Header)>
                {
                    ((EncryptedCek: encryptedCek, Header: new Dictionary<string, object>())),
                };

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
            var recipients = new List<(byte[] EncryptedCek, IDictionary<string, object> Header)>();

           IEnumerable _recipients = Dictionaries.Get<IEnumerable>(json, "recipients");

            if (_recipients != null)
            {
                foreach (IDictionary<string, object> recipient in _recipients)
                {
                    byte[] encryptedCek = Base64Url.Decode(Dictionaries.Get<string>(recipient, "encrypted_key"));
                    recipients.Add((EncryptedCek: encryptedCek, Header: Dictionaries.Get<IDictionary<string, object>>(recipient, "header")));
                }
            }
            else if (recipients.Count == 0)
            {
                byte[] encryptedCek = Base64Url.Decode(Dictionaries.Get<string>(json, "encrypted_key"));
                recipients.Add((EncryptedCek: encryptedCek, Header: Dictionaries.Get<IDictionary<string, object>>(json, "header")));
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