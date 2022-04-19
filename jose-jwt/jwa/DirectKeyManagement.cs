using System;
using System.Collections.Generic;

namespace Jose
{
    public class DirectKeyManagement : IKeyManagement
    {
        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            return new [] { byteKey(key), Arrays.Empty};
        }

        public byte[] WrapKey(byte[] cek, object key, IDictionary<string, object> header)
        {
            throw new JoseException("Direct Encryption not supported for multi-recipient JWE.");
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            Ensure.IsEmpty(encryptedCek, "DirectKeyManagement expects empty content encryption key.");

            return byteKey(key);
        }

        private byte[] byteKey(object key)
        {
            if (key is byte[] arr)
            {
                return arr;
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.OCT)
                {
                    return jwk.OctKey();
                }
            }

            throw new ArgumentException("DirectKeyManagement alg expects key to be byte[] array or Jwk with kty='oct'");
        }
    }
}