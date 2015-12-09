using System;
using System.Collections.Generic;

namespace Jose
{
    public class EcdhKeyManagementWithAesKeyWrap : EcdhKeyManagement
    {
        private AesKeyWrapManagement aesKW;
        private int keyLengthBits;

        public EcdhKeyManagementWithAesKeyWrap(int keyLengthBits, AesKeyWrapManagement aesKw):base(false)
        {
            aesKW = aesKw;
            this.keyLengthBits = keyLengthBits;
        }

        public override byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            byte[][] agreement = base.WrapNewKey(keyLengthBits, key, header);

            byte[] kek = agreement[0]; //use agreed key as KEK for AES-KW

            return aesKW.WrapNewKey(cekSizeBits, kek, header);
        }

        public override byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            byte[] kek = base.Unwrap(Arrays.Empty, key, keyLengthBits, header);

            return aesKW.Unwrap(encryptedCek, kek, cekSizeBits, header);
        }
    }
}