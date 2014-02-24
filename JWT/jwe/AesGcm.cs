using System;
using System.IO;
using System.Security.Cryptography;
using Security.Cryptography;

namespace Json
{
    public class AesGcm : IJweAlgorithm
    {
        private int keyLength;

        public AesGcm(int keyLength)
        {
            this.keyLength = keyLength;
        }

        public byte[][] Encrypt(byte[] aad, byte[] plainText, byte[] cek)
        {
            Ensure.BitSize(cek, keyLength, string.Format("AES-GCM algorithm expected key of size {0} bits, but was given {1} bits",keyLength, cek.Length * 8));

            byte[] iv = Arrays.Random(96);

            byte[] authTag;
            byte[] cipherText;

            try
            {
                using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
                {
                    aes.CngMode = CngChainingMode.Gcm;
                    aes.Key = cek;
                    aes.IV = iv;
                    aes.AuthenticatedData = aad;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (IAuthenticatedCryptoTransform encryptor = aes.CreateAuthenticatedEncryptor())
                        {
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(plainText, 0, plainText.Length);

                                cs.FlushFinalBlock();
                                authTag = encryptor.GetTag();
                                cipherText = ms.ToArray();

                                return new[] { iv, cipherText, authTag };
                            }
                        }
                    }
                }
            }
            catch (CryptographicException e)
            {
                throw new EncryptionException("Unable to encrypt content.",e);    
            }            
        }

        public byte[] Decrypt(byte[] aad, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag)
        {
            Ensure.BitSize(cek, keyLength, string.Format("AES-GCM algorithm expected key of size {0} bits, but was given {1} bits",keyLength, cek.Length * 8));

            try
            {
                using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
                {
                    aes.CngMode = CngChainingMode.Gcm;
                    aes.Key = cek;
                    aes.IV = iv;
                    aes.AuthenticatedData = aad;
                    aes.Tag = authTag;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (ICryptoTransform decryptor = aes.CreateDecryptor())
                        {
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(cipherText, 0, cipherText.Length);

                                cs.FlushFinalBlock();

                                return ms.ToArray();
                            }
                        }
                    }
                }
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