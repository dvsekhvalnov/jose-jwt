using System;
using System.IO;
using System.Security.Cryptography;
using Security.Cryptography;

namespace Json
{
    public class AesGcm : IJweAlgorithm
    {
//        private int 

        public byte[][] Encrypt(byte[] aad, byte[] plainText, byte[] cek)
        {
            throw new NotImplementedException();
        }
        //iv - 96 bit
        //authtag 128bit
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
                        cs.FlushFinalBlock();

                        byte[] plaintext = ms.ToArray();

                        return plaintext;
                    }


                }
            }
        }

        public int KeySize
        {
            get { throw new NotImplementedException(); }
        }
    }
}