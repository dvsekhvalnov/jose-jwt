using System.Security.Cryptography;
using Jose.jwe;

namespace Jose
{
    public class AesGcmEncryption : IJweAlgorithm
    {
        private int keyLength;

        public AesGcmEncryption(int keyLength)
        {
            this.keyLength = keyLength;
        }

        public byte[][] Encrypt(byte[] aad, byte[] plainText, byte[] cek)
        {
            Ensure.BitSize(cek, keyLength, string.Format("AES-GCM algorithm expected key of size {0} bits, but was given {1} bits",keyLength, cek.Length * 8L));

            byte[] iv = Arrays.Random(96);

            try
            {
                byte[][] cipherAndTag=AesGcm.Encrypt(cek, iv, aad, plainText);

                return new[] { iv, cipherAndTag[0], cipherAndTag[1] };
            }
            catch (CryptographicException e)
            {
                throw new EncryptionException("Unable to encrypt content.",e);    
            }            
        }

        public byte[] Decrypt(byte[] aad, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag)
        {
            Ensure.BitSize(cek, keyLength, string.Format("AES-GCM algorithm expected key of size {0} bits, but was given {1} bits",keyLength, cek.Length * 8L));

            try
            {
                return AesGcm.Decrypt(cek, iv, aad, cipherText, authTag);
            }
            catch (CryptographicException e)
            {
                throw new EncryptionException("Unable to decrypt content or authentication tag do not match.", e);
            }
        }

        public int KeySize
        {
            get { return keyLength; }
        }
    }
}