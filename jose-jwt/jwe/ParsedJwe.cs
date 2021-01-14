namespace Jose.Jwe
{
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Internal class used to represent the data withing a JWE
    /// Note - could have come in as compant, flattened json or general json.
    /// </summary>
    internal class ParsedJwe
    {
        internal static ParsedJwe Parse(string jwe, SerializationMode mode, JwtSettings settings)
        {
            switch (mode)
            {
                case SerializationMode.smCompact:
                    {
                        return ParseCompact(jwe);
                    }

                case SerializationMode.smJson:
                    {
                        return ParseJson(jwe, settings);
                    }

                default:
                    throw new JoseException($"Unsupported serializtion mode: {mode}");
            }
        }

        internal byte[] ProtectedHeaderBytes { get; }
        internal IDictionary<string, object> UnprotectedHeader { get; }
        internal List<(byte[] EncryptedCek, IDictionary<string, object> Header)> Recipients { get; }
        internal byte[] Aad { get; }
        internal byte[] Iv { get; }
        internal byte[] Ciphertext { get; }
        internal byte[] AuthTag { get; }

        private ParsedJwe(
            byte[] protectedHeaderBytes,
            IDictionary<string, object> unprotectedHeader,
            List<(byte[] EncryptedCek, IDictionary<string, object> Header)> recipients,
            byte[] aad,
            byte[] iv,
            byte[] ciphertext,
            byte[] authTag)
        {
            this.ProtectedHeaderBytes = protectedHeaderBytes;
            this.UnprotectedHeader = unprotectedHeader;
            this.Recipients = recipients;
            this.Aad = aad;
            this.Iv = iv;
            this.Ciphertext = ciphertext;
            this.AuthTag = authTag;
        }

        private static ParsedJwe ParseCompact(string jwe)
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

            return new ParsedJwe(
                protectedHeaderBytes: protectedHeaderBytes,
                unprotectedHeader: null,
                aad: null,
                recipients: recipients,
                iv: iv,
                ciphertext: ciphertext,
                authTag: authTag);
        }

        private static ParsedJwe ParseJson(string jwe, JwtSettings settings)
        {
            // TODO - do we want the entire object deserialized using the custom JsonMapper?
            var jweJson = settings.JsonMapper.Parse<JweJson>(jwe);

            var recipients = new List<(byte[] EncryptedCek, IDictionary<string, object> Header)>();
            if (jweJson.recipients?.Count() > 0)
            {
                foreach (var recipient in jweJson.recipients)
                {
                    byte[] encryptedCek = Base64Url.Decode(recipient.encrypted_key);
                    recipients.Add((EncryptedCek: encryptedCek, Header: recipient.header));
                }
            }
            else
            {
                byte[] encryptedCek = Base64Url.Decode(jweJson.encrypted_key);
                recipients.Add((EncryptedCek: encryptedCek, Header: jweJson.header));
            }

            return new ParsedJwe(
                protectedHeaderBytes: Base64Url.Decode(jweJson.@protected),
                unprotectedHeader: jweJson.unprotected,
                aad: jweJson.aad == null ? null : Base64Url.Decode(jweJson.aad),
                recipients: recipients,
                iv: Base64Url.Decode(jweJson.iv),
                ciphertext: Base64Url.Decode(jweJson.ciphertext),
                authTag: Base64Url.Decode(jweJson.tag));
        }
    }
}