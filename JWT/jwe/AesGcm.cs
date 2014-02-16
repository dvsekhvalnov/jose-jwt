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
            byte[] iv = Arrays.Random(96);

            byte[] authTag;
            byte[] cipherText;

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

                            // Finish the encryption and get the output authentication tag and ciphertext
                            cs.FlushFinalBlock();
                            authTag = encryptor.GetTag();
                            cipherText = ms.ToArray();
                        }
                    }
                }
            }

            return new[] { iv, cipherText, authTag };
        }

        public byte[] Decrypt(byte[] aad, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag)
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
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherText, 0, cipherText.Length);

                        // If the authentication tag does not match, we'll fail here with a
                        // CryptographicException, and the ciphertext will not be decrypted.
                        //TODO: should we catch it?
                        cs.FlushFinalBlock();

                        byte[] plaintext = ms.ToArray();

                        return plaintext;
                    }
                }
            }
        }

        public int KeySize
        {
            get { return keyLength; }
        }
    }
}