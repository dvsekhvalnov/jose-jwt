using System;
using System.Security.Cryptography;

namespace Jose
{
    public class HmacUsingSha : IJwsAlgorithm
    {
        private readonly string hashMethod;

        public HmacUsingSha(string hashMethod)
        {
            this.hashMethod = hashMethod;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
            if (key is byte[] keyBytes)
            {
                using (var sha = KeyedHash(keyBytes))
                {
                    return sha.ComputeHash(securedInput);
                }
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.OCT)
                {
                    using (var sha = KeyedHash(jwk.OctKey()))
                    {
                        return sha.ComputeHash(securedInput);
                    }
                }
            }

            throw new ArgumentException("HmacUsingSha alg expects key to be byte[] array or Jwk with kty='oct'");
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
            else if ("SHA384".Equals(hashMethod))
                return new HMACSHA384(key);
            else if ("SHA512".Equals(hashMethod))
                return new HMACSHA512(key);
            else
                throw new ArgumentException("Unsupported hashing algorithm: '{0}'", hashMethod);
        }
    }
}