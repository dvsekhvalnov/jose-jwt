using System.Collections.Generic;
using System.Security.Cryptography;

namespace Jose
{
    public class RsaKeyManagement:IKeyManagement
    {        
        private bool useRsaOaepPadding; //true for RSA-OAEP, false for RSA-PKCS#1 v1.5

        public RsaKeyManagement(bool useRsaOaepPadding)
        {            
            this.useRsaOaepPadding = useRsaOaepPadding;
        }

        public byte[] NewKey(int keyLength, object key, IDictionary<string, object> header)
        {            
            return Arrays.Random(keyLength);
        }

        public byte[] Wrap(byte[] cek, object key, IDictionary<string, object> header)
        {
            var publicKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return publicKey.Encrypt(cek, useRsaOaepPadding);
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            var privateKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return privateKey.Decrypt(encryptedCek, useRsaOaepPadding);
        }
    }
}