using System;
using System.IO;
using System.Security.Cryptography;
using Jose.jwe;

namespace Jose
{
    public class AesCbcHmacEncryption : IJweAlgorithm
    {
        private IJwsAlgorithm hashAlgorithm;

        private readonly int keyLength;

        public AesCbcHmacEncryption(IJwsAlgorithm hashAlgorithm, int keyLength)
        {
            this.hashAlgorithm = hashAlgorithm;
            this.keyLength = keyLength;
        }

        public byte[][] Encrypt(byte[] aad, byte[] plainText, byte[] cek)
        {
            Ensure.BitSize(cek, keyLength, string.Format("AES-CBC with HMAC algorithm expected key of size {0} bits, but was given {1} bits", keyLength, cek.Length * 8L));

            byte[] hmacKey = Arrays.FirstHalf(cek);
            byte[] aesKey = Arrays.SecondHalf(cek);

            byte[] iv = Arrays.Random();

            byte[] cipherText;

            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = aesKey;
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
            }
            catch (CryptographicException e)
            {
                throw new EncryptionException("Unable to encrypt content.", e);    
            }

            byte[] authTag = ComputeAuthTag(aad, iv, cipherText, hmacKey);

            return new[] {iv, cipherText, authTag};
        }

        public byte[] Decrypt(byte[] aad, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag)
        {
            Ensure.BitSize(cek, keyLength, string.Format("AES-CBC with HMAC algorithm expected key of size {0} bits, but was given {1} bits", keyLength, cek.Length * 8L));

            byte[] hmacKey = Arrays.FirstHalf(cek);
            byte[] aesKey = Arrays.SecondHalf(cek);

            // Check MAC
            byte[] expectedAuthTag = ComputeAuthTag(aad, iv, cipherText, hmacKey);

            if (!Arrays.ConstantTimeEquals(expectedAuthTag, authTag))
            {
                throw new IntegrityException("Authentication tag do not match.");
            }

            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = aesKey;
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
            catch (CryptographicException e)
            {
                throw new EncryptionException("Unable to decrypt content", e);
            }
        }

        public int KeySize
        {
            get { return keyLength; }
        }

        private byte[] ComputeAuthTag(byte[] aad, byte[] iv, byte[] cipherText, byte[] hmacKey)
        {
            byte[] al = Arrays.LongToBytes(aad.Length * 8L);
            byte[] hmacInput = Arrays.Concat(aad, iv, cipherText, al);

            byte[] hmac = hashAlgorithm.Sign(hmacInput, hmacKey);

            return Arrays.FirstHalf(hmac);
        }

    }
}