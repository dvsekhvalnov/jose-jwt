using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Json
{
    public class AES
    {
        public static byte[] Encrypt(byte[] plainText, byte[] key, byte[] iv)
        {
            byte[] cipherText;

            using (Aes aes = new AesManaged())
            {
                aes.Key = key;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        using (CryptoStream encrypt = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            encrypt.Write(plainText, 0, plainText.Length);
                            encrypt.FlushFinalBlock();

                            cipherText = ms.ToArray();
                        }
                    }
                }

            }

            return cipherText;
        }

        public static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            string plaintext;

            using (Aes aes = new AesManaged())
            {
                aes.Key = key;
                aes.IV = iv;                

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }

            return Encoding.UTF8.GetBytes(plaintext);
        }
    }
}
