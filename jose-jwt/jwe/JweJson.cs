#if NETSTANDARD
namespace Jose.Jwe
{
    using Newtonsoft.Json;
    using System.Collections.Generic;

    /// <summary>
    /// Internal class used as helper deserialize Json Serialized JWE
    /// </summary>
    internal class JweJson
    {
        [JsonProperty("protected")]
        internal string Protected { get; set; }

        [JsonProperty("unprotected")]
        internal IDictionary<string, object> Unprotected { get; set; }

        [JsonProperty("iv")]
        internal string Iv { get; set; }

        [JsonProperty("aad")]
        internal string Aad { get; set; }

        [JsonProperty("ciphertext")]
        internal string Ciphertext { get; set; }

        [JsonProperty("tag")]
        internal string Tag { get; set; }
  
        [JsonProperty("recipients")]
        internal IEnumerable<RecipientJson> Recipients { get; set; }
  
        [JsonProperty("encrypted_key")]
        internal string EncryptedKey { get; set; }

        [JsonProperty("header")]
        internal IDictionary<string, object> Header { get; set; }
    }

    internal class RecipientJson
    {
        [JsonProperty("encrypted_key")]
        internal string EncryptedKey { get; set; }

        [JsonProperty("header")]
        internal IDictionary<string, object> Header { get; set; }
    }
}
#endif //NETSTANDARD2_1