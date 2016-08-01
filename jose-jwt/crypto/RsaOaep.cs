using System;
using System.Security.Cryptography;
using Jose.native;

namespace Jose
{
    public static class RsaOaep
    {
        public static byte[] Decrypt(byte[] cipherText, CngKey key, CngAlgorithm hash)
        {
            var paddingInfo = new BCrypt.BCRYPT_OAEP_PADDING_INFO(hash.Algorithm);

            uint plainTextByteSize;
            uint status = NCrypt.NCryptDecrypt(key.Handle, cipherText, cipherText.Length, ref paddingInfo, null, 0, out plainTextByteSize, BCrypt.BCRYPT_PAD_OAEP);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("NCrypt.Decrypt() (plaintext buffer size) failed with status code:{0}", status));

            var plainText=new byte[plainTextByteSize];

            status = NCrypt.NCryptDecrypt(key.Handle, cipherText, cipherText.Length, ref paddingInfo, plainText, plainTextByteSize, out plainTextByteSize, BCrypt.BCRYPT_PAD_OAEP);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("NCrypt.Decrypt() failed with status code:{0}", status));

            return plainText;
        }

        public static byte[] Encrypt(byte[] plainText, CngKey key, CngAlgorithm hash)
        {
            var paddingInfo = new BCrypt.BCRYPT_OAEP_PADDING_INFO(hash.Algorithm);

            uint cipherTextByteSize;
            uint status = NCrypt.NCryptEncrypt(key.Handle, plainText, plainText.Length, ref paddingInfo, null, 0, out cipherTextByteSize, BCrypt.BCRYPT_PAD_OAEP);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("NCrypt.Encrypt() (ciphertext buffer size) failed with status code:{0}", status));

            var cipherText = new byte[cipherTextByteSize];

            status = NCrypt.NCryptEncrypt(key.Handle, plainText, plainText.Length, ref paddingInfo, cipherText, cipherTextByteSize, out cipherTextByteSize, BCrypt.BCRYPT_PAD_OAEP);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("NCrypt.Encrypt() failed with status code:{0}", status));

            return cipherText;
        }
    }
}