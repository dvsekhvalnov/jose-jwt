using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Jose
{
    public class JWK
    {        
        public static class KeyTypes
        {
            public const string OCT = "oct";
            public const string EC = "EC";
            public const string RSA = "RSA";
        }

        public static class Usage
        {
            public const string Signature = "sig";
            public const string Encryption = "enc";
        }

        private byte[] octKey;
        private RSA rsaKey;

        // General
        public string Kty { get; set; }
        public string Use { get; set; }
        public string Alg { get; set; }
        public string KeyId { get; set; }
        public List<string> KeyOps { get; set; }

        // Symmetric keys
        public string K { get; set; }       

        // Elliptic keys

        // RSA keys

        // Modulus
        public string N { get; set; }

        // Public exponent
        public string E { get; set; }

        // Private exponent
        public string D { get; set; }

        // First prime
        public string P { get; set; }

        // First factor CRT exponent
        public string DP { get; set; }

        // Second prime
        public string Q { get; set; }

        // Second factor CRT exponent
        public string DQ { get; set; }

        // First CRT coefficient
        public string QI { get; set; }

        public RSA RsaKey()
        {
            if (rsaKey == null && E != null && N != null)
            {
                RSAParameters param = new RSAParameters();
                param.Modulus = Base64Url.Decode(N);
                param.Exponent = Base64Url.Decode(E);

                rsaKey = RSA.Create();
                rsaKey.ImportParameters(param);
            }

            return rsaKey;
        }

        public byte[] OctKey()
        {
            if (octKey == null && K != null)
            {
                octKey = Base64Url.Decode(K);
            }

            return octKey;
        }

        public JWK()
        {

        }

        public JWK(byte[] key)
        {
            Kty = KeyTypes.OCT;
            K = Base64Url.Encode(key);
            octKey = key;
        }

        public JWK(RSA key, bool isPrivate = true)
        {
            rsaKey = key;
            Kty = KeyTypes.RSA;

            RSAParameters param = key.ExportParameters(isPrivate);

            N = Base64Url.Encode(param.Modulus);
            E = Base64Url.Encode(param.Exponent);

            if (param.D !=null)
            {
                D = Base64Url.Encode(param.D);
            }

            if (param.P !=null)
            {
                P = Base64Url.Encode(param.P);
            }

            if (param.DP !=null)
            {
                DP = Base64Url.Encode(param.DP);
            }

            if (param.Q !=null)
            {
                Q = Base64Url.Encode(param.Q);
            }

            if (param.DQ !=null)
            {
                DQ = Base64Url.Encode(param.DQ);
            }

            if (param.InverseQ !=null)
            {
                QI = Base64Url.Encode(param.InverseQ);
            }
        }

        public IDictionary<string, object> ToDictionary()
        {
            var result = new Dictionary<string, Object>();

            result["kty"] = Kty;

            if(Use != null) { result["use"] = Use; }
            if(KeyOps != null) { result["key_ops"] = KeyOps; }
            if(Alg != null) { result["alg"] = Alg; }
            
            if (Kty == JWK.KeyTypes.OCT)
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
                Alg = Dictionaries.Get<string>(data, "alg"),
                KeyId = Dictionaries.Get<string>(data, "kid"),
                KeyOps = Dictionaries.Get<List<string>>(data, "key_ops"),

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
