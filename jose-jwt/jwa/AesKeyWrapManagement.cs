using System;
using System.Collections.Generic;

namespace Jose
{
    public class AesKeyWrapManagement : IKeyManagement
    {
        private readonly int kekLengthBits;

        public AesKeyWrapManagement(int kekLengthBits)
        {
            this.kekLengthBits = kekLengthBits;
        }

        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var cek = Arrays.Random(cekSizeBits);

            return new byte[][] { cek, this.WrapKey(cek, key, header) };
        }

        public byte[] WrapKey(byte[] cek, object key, IDictionary<string, object> header)
        {
            byte[] sharedKey = byteKey(key);

            Ensure.BitSize(sharedKey, kekLengthBits, string.Format("AesKeyWrap management algorithm expected key of size {0} bits, but was given {1} bits", kekLengthBits, sharedKey.Length * 8L));

            return AesKeyWrap.Wrap(cek, sharedKey);
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            var sharedKey = byteKey(key);

            Ensure.BitSize(sharedKey, kekLengthBits, string.Format("AesKeyWrap management algorithm expected key of size {0} bits, but was given {1} bits", kekLengthBits, sharedKey.Length * 8L));

            return AesKeyWrap.Unwrap(encryptedCek, sharedKey);
        }

        private byte[] byteKey(object key)
        {
            if (key is byte[])
            {
                return (byte[])key;
            }

            if (key is JWK)
            {
                var jwk = (JWK)key;

                if (jwk.Kty == JWK.KeyTypes.OCT)
                {
                    return jwk.OctKey();
                }
            }

            throw new ArgumentException("AesKeyWrap management algorithm expectes key to be byte[] array or JWK with kty='oct'");
        }
    }
}