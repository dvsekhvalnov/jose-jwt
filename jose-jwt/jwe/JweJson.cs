namespace Jose.Jwe
{
    using System.Collections.Generic;

    /// <summary>
    /// public class used as helper deserialize Json Serialized JWE
    /// </summary>
    public class JweJson
    {
        public string @protected { get; set; }

        public IDictionary<string, object> unprotected { get; set; }

        public string iv { get; set; }

        public string aad { get; set; }

        public string ciphertext { get; set; }

        public string tag { get; set; }
  
        public IEnumerable<RecipientJson> recipients { get; set; }
  
        public string encrypted_key { get; set; }

        public IDictionary<string, object> header { get; set; }
    }

    public class RecipientJson
    {
        public string encrypted_key { get; set; }

        public IDictionary<string, object> header { get; set; }
    }
}