using System;
using System.Collections.Generic;

namespace Jose
{
    public class AesGcmKeyWrapManagement : IKeyManagement
    {
        private readonly int keyLengthBits;

        public AesGcmKeyWrapManagement(int keyLengthBits)
        {
            this.keyLengthBits = keyLengthBits;
        }

        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var cek = Arrays.Random(cekSizeBits);

            return new byte[][] { cek, this.WrapKey(cek, key, header) };
        }

        public byte[] WrapKey(byte[] cek, object key, IDictionary<string, object> header)
        {
            byte[] sharedKey = byteKey(key);            

            Ensure.BitSize(sharedKey, keyLengthBits, string.Format("AesGcmKeyWrapManagement management algorithm expected key of size {0} bits, but was given {1} bits", keyLengthBits, sharedKey.Length * 8L));

            byte[] iv = Arrays.Random(96);

            byte[][] cipherAndTag = AesGcm.Encrypt(sharedKey, iv, null, cek);

            header["iv"] = Base64Url.Encode(iv);
            header["tag"] = Base64Url.Encode(cipherAndTag[1]);

            return cipherAndTag[0];
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            byte[] sharedKey = byteKey(key);

            Ensure.BitSize(sharedKey, keyLengthBits, string.Format("AesGcmKeyWrapManagement management algorithm expected key of size {0} bits, but was given {1} bits", keyLengthBits, sharedKey.Length * 8L));

            Ensure.Contains(header, new[] { "iv" }, "AesGcmKeyWrapManagement algorithm expects 'iv' param in JWT header, but was not found");
            Ensure.Contains(header, new[] { "tag" }, "AesGcmKeyWrapManagement algorithm expects 'tag' param in JWT header, but was not found");

            byte[] iv = Base64Url.Decode((string)header["iv"]);
            byte[] authTag = Base64Url.Decode((string)header["tag"]);

            return AesGcm.Decrypt(sharedKey, iv, null, encryptedCek, authTag);
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

            throw new ArgumentException("AesGcmKeyWrapManagement management algorithm expects key to be byte[] array or Jwk with kty='oct'");
        }
    }
}