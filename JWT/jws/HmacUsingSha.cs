using System;
using System.Security.Cryptography;

namespace Jose
{
    public class HmacUsingSha : IJwsAlgorithm
    {
        private string hashMethod;

        public HmacUsingSha(string hashMethod)
        {
            this.hashMethod = hashMethod;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
            var sharedKey = Ensure.Type<byte[]>(key, "HmacUsingSha alg expectes key to be byte[] array.");

            using (var sha = KeyedHash(sharedKey)) 
            {
                return sha.ComputeHash(securedInput); 
            }
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
            byte[] expected = Sign(securedInput, key);

            return Arrays.ConstantTimeEquals(signature, expected);            
        }

        private KeyedHashAlgorithm KeyedHash(byte[] key)
        {
            if ("SHA256".Equals(hashMethod))
                return new HMACSHA256(key);
            if ("SHA384".Equals(hashMethod))
                return new HMACSHA384(key);
            if ("SHA512".Equals(hashMethod))
                return new HMACSHA512(key);

            throw new ArgumentException("Unsupported hashing algorithm: '{0}'", hashMethod);
        }
    }
}