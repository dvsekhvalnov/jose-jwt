#if NETSTANDARD
namespace Jose.jwe
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
            if (jweJson.Recipients?.Count() > 0)
            {
                foreach (var recipient in jweJson.Recipients)
                {
                    byte[] encryptedCek = Base64Url.Decode(recipient.EncryptedKey);
                    recipients.Add((EncryptedCek: encryptedCek, Header: recipient.Header));
                }
            }
            else
            {
                byte[] encryptedCek = Base64Url.Decode(jweJson.EncryptedKey);
                recipients.Add((EncryptedCek: encryptedCek, Header: jweJson.Header));
            }

            return new ParsedJwe(
                protectedHeaderBytes: Base64Url.Decode(jweJson.Protected),
                unprotectedHeader: jweJson.Unprotected,
                aad: jweJson.Aad == null ? null : Base64Url.Decode(jweJson.Aad),
                recipients: recipients,
                iv: Base64Url.Decode(jweJson.Iv),
                ciphertext: Base64Url.Decode(jweJson.Ciphertext),
                authTag: Base64Url.Decode(jweJson.Tag));
        }
    }
}
#endif //NETSTANDARD2_1