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

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream encrypt = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        
                            encrypt.Write(plainText,0,plainText.Length);
                            encrypt.FlushFinalBlock();

                            cipherText = ms.ToArray();
                    }
                }

            }

            return cipherText;
        }

        public static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            string plaintext;

            using (Aes rijAlg = new AesManaged())
            {
                rijAlg.Key = key;
                rijAlg.IV = iv;

                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
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

            return Encoding.UTF8.GetBytes(plaintext);
        }

        public static byte[] GenerateKey(int keySizeBits)
        {
            var aes = new AesManaged {KeySize = keySizeBits};

            aes.GenerateKey();

            return aes.Key;
        }

        public static byte[] GenerateIV()
        {
            var aes = new AesManaged();            

            aes.GenerateIV();

            return aes.IV;
        }
    }
}
