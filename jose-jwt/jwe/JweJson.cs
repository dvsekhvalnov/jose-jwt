namespace Jose.jwe
{
    using Newtonsoft.Json;
    using System.Collections.Generic;

    internal abstract class JweJson
    {
        [JsonProperty("protected")]
        internal string Protected { get; set; }

        [JsonProperty("unprotected")]
        internal string Unprotected { get; set; }

        [JsonProperty("iv")]
        internal string Iv { get; set; }

        [JsonProperty("aad")]
        internal string Aad { get; set; }

        [JsonProperty("ciphertext")]
        internal string Ciphertext { get; set; }

        [JsonProperty("tag")]
        internal string Tag { get; set; }
    }

    internal class GeneralJweJson : JweJson
    {

        [JsonProperty("recipients")]
        internal IEnumerable<JweRecipientDto> Recipients { get; set; }
    }

    internal class FlattenedJweJson : JweJson
    {
        [JsonProperty("encrypted_key")]
        internal string EncryptedKey { get; set; }

        [JsonProperty("header")]
        internal IDictionary<string, object> Header { get; set; }
    }

    internal class JweRecipientDto
    {
        [JsonProperty("encrypted_key")]
        internal string EncryptedKey { get; set; }

        [JsonProperty("header")]
        internal IDictionary<string, object> Header { get; set; }
    }
}