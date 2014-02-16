using System.Security.Cryptography;

namespace Json
{
    public class RsaKeyManagement:IKeyManagement
    {        
        private bool useRsaOaepPadding; //true for RSA-OAEP, false for RSA-PKCS#1 v1.5

        public RsaKeyManagement(bool useRsaOaepPadding)
        {            
            this.useRsaOaepPadding = useRsaOaepPadding;
        }

        public byte[] NewKey(int keyLength)
        {
            return Arrays.Random(keyLength);
        }

        public byte[] Wrap(byte[] cek, object key)
        {
            var publicKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return publicKey.Encrypt(cek, useRsaOaepPadding);
        }

        public byte[] Unwrap(byte[] encryptedCek, object key)
        {
            var privateKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return privateKey.Decrypt(encryptedCek, useRsaOaepPadding);
        }
    }
}