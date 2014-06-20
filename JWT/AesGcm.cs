using System;
using System.IO;
using System.Security.Cryptography;
using Security.Cryptography;

namespace Jose
{
    public static class AesGcm
    {
        /// <summary>
        /// Performs AES encryption in GCM chaining mode over plain text
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="aad"></param>
        /// <param name="plainText"></param>
        /// <returns>2 byte[] arrays: [0]=cipher text, [1]=authentication tag</returns>
        public static byte[][] Encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plainText)
        {
            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                aes.CngMode = CngChainingMode.Gcm;
                aes.Key = key;
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

                            return new[] { ms.ToArray(), encryptor.GetTag() };
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Performs AES decryption in GCM chaning mode over cipher text
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="aad"></param>
        /// <param name="cipherText"></param>
        /// <param name="authTag"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] key, byte[] iv, byte[] aad, byte[] cipherText, byte[] authTag)
        {
            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                aes.CngMode = CngChainingMode.Gcm;
                aes.Key = key;
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
    }
}