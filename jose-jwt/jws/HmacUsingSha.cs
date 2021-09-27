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
            if (key is byte[])
            {
                using (var sha = KeyedHash((byte[])key))
                {
                    return sha.ComputeHash(securedInput);
                }
            }

            if (key is JWK)
            {
                var jwk = (JWK)key;

                if (jwk.Kty == JWK.Oct)
                {
                    using (var sha = KeyedHash(jwk.OctKey()))
                    {
                        return sha.ComputeHash(securedInput);
                    }
                }
            }

            throw new ArgumentException("HmacUsingSha alg expectes key to be byte[] array or JWK with kty='oct'");
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