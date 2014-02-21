using System.IO;
using System.Security.Cryptography;

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
            using (Aes aes = new AesManaged())
            {
                aes.Key = key;
                aes.IV = iv;                

                using (MemoryStream ms = new MemoryStream())
                {
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
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
