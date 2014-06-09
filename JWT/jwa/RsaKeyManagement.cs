using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Jose
{
    public class RsaKeyManagement:IKeyManagement
    {        
        private bool useRsaOaepPadding; //true for RSA-OAEP, false for RSA-PKCS#1 v1.5

        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {            
            var publicKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            var cek = Arrays.Random(cekSizeBits);
            var encryptedCek = publicKey.Encrypt(cek, useRsaOaepPadding);

            return new[] {cek, encryptedCek};
        }

        public RsaKeyManagement(bool useRsaOaepPadding)
        {            
            this.useRsaOaepPadding = useRsaOaepPadding;
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            var privateKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return privateKey.Decrypt(encryptedCek, useRsaOaepPadding);
        }
    }
}