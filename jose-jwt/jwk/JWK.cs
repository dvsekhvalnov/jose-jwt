using System;
using System.Collections.Generic;

namespace Jose
{
    public class JWK
    {
        public const string Oct = "oct";
        public const string EC = "EC";
        public const string RSA = "RSA";
        public const string Signature = "sig";
        public const string Encryption = "enc";

        private byte[] octKey;

        // General
        public string Kty { get; set; }
        public string Use { get; set; }
        public string Alg { get; set; }
        public string Key { get; set; }
        public string[] KeyOps { get; }

        // Symmetric keys
        public string K { get; set; }

        public byte[] OctKey()
        {
            if (octKey == null && K != null)
            {
                octKey = Base64Url.Decode(K);
            }

            return octKey;            
        }

        // Elliptic keys

        // Assymetric keys

        public JWK(byte[] key)
        {
            Kty = Oct;
            K = Base64Url.Encode(key);
            octKey = key;
        }

        public JWK()
        {

        }

        public IDictionary<string, object> ToDictionary()
        {
            var result = new Dictionary<string, Object>();

            result["kty"] = Kty;
            
            if (Kty == JWK.Oct)
            {
                result["k"] = K;
            }

            return result;
        }

        public static JWK FromDictionary(IDictionary<string, object> data)
        {
            var key = new JWK
            {
                Kty = Dictionaries.Get<string>(data, "kty"),                
                Use = Dictionaries.Get<string>(data, "user"),                
                K = Dictionaries.Get<string>(data, "k"),                
            };
            

            return key;
        }

        public string ToJson(IJsonMapper mapper = null)
        {
            return mapper.Serialize(ToDictionary());
        }

        public static JWK FromJson(string json, IJsonMapper mapper = null)
        {
            return JWK.FromDictionary(
                mapper.Parse<IDictionary<string, object>>(json)
            );
        }
    }
}
