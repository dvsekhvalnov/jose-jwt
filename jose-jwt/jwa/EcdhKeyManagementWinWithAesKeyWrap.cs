using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Jose
{
    public class EcdhKeyManagementWinWithAesKeyWrap : EcdhKeyManagementWin
    {
        private readonly AesKeyWrapManagement aesKW;
        private readonly int keyLengthBits;
        private readonly EcdhKeyManagementUnixWithAesKeyWrap ecdhKeyManagementUnixWithAesKeyWrap;

        public EcdhKeyManagementWinWithAesKeyWrap(int keyLengthBits, AesKeyWrapManagement aesKw, EcdhKeyManagementUnixWithAesKeyWrap ecdhKeyManagementUnixWithAesKeyWrap) : base(false, ecdhKeyManagementUnixWithAesKeyWrap)
        {
            aesKW = aesKw;
            this.keyLengthBits = keyLengthBits;
            this.ecdhKeyManagementUnixWithAesKeyWrap = ecdhKeyManagementUnixWithAesKeyWrap;
        }

        public override byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
    #if NET472 || NETSTANDARD2_1
            if (key is ECDiffieHellman || key is ECDsa || key is Jwk)
            {
                return ecdhKeyManagementUnixWithAesKeyWrap.WrapNewKey(cekSizeBits, key, header);
            }
    #endif        
            var cek = Arrays.Random(cekSizeBits);

            return new byte[][] { cek, this.WrapKey(cek, key, header) };
        }

        public override byte[] WrapKey(byte[] cek, object key, IDictionary<string, object> header)
        {
    #if NET472 || NETSTANDARD2_1
            if (key is ECDiffieHellman || key is ECDsa || key is Jwk)
            {
                return ecdhKeyManagementUnixWithAesKeyWrap.WrapKey(cek, key, header);
            }
    #endif        
            byte[][] agreement = base.WrapNewKey(keyLengthBits, key, header);

            byte[] kek = agreement[0]; //use agreed key as KEK for AES-KW

            return aesKW.WrapKey(cek, kek, header);
        }

        public override byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
    #if NET472 || NETSTANDARD2_1
            if (key is ECDiffieHellman || key is ECDsa || key is Jwk)
            {
                return ecdhKeyManagementUnixWithAesKeyWrap.Unwrap(encryptedCek, key, cekSizeBits, header);
            }
    #endif        
            byte[] kek = base.Unwrap(Arrays.Empty, key, keyLengthBits, header);

            return aesKW.Unwrap(encryptedCek, kek, cekSizeBits, header);
        }
    }
}