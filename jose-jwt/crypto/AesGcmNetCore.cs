#if NETSTANDARD2_1 || NET
using System.Security.Cryptography;

namespace Jose
{
    public static class AesGcm
    {
        /// <summary>
        /// Performs AES encryption in GCM chaining mode over plain text
        /// </summary>
        /// <param name="key">aes key</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="aad">additional authn data</param>
        /// <param name="plainText">plain text message to be encrypted</param>
        /// <returns>2 byte[] arrays: [0]=cipher text, [1]=authentication tag</returns>
        /// /// <exception cref="CryptographicException">if encryption failed by any reason</exception>
        public static byte[][] Encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plainText)
        {
#if NET
            using var gcm =
                new System.Security.Cryptography.AesGcm(key, System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize);
#elif NETSTANDARD2_1
            using var gcm = new System.Security.Cryptography.AesGcm(key);
#endif

            var ciphertext = new byte[plainText.Length];
            var tag = new byte[System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize];

            gcm.Encrypt(nonce: iv, plaintext: plainText, ciphertext: ciphertext, tag: tag, associatedData: aad);

            return new byte[][] { ciphertext, tag };
        }

        /// <summary>
        /// Performs AES decryption in GCM chaning mode over cipher text
        /// </summary>
        /// <param name="key">aes key</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="aad">additional authn data</param>
        /// <param name="plainText">plain text message to be encrypted</param>
        /// <returns>decrypted plain text messages</returns>
        /// <exception cref="CryptographicException">if decryption failed by any reason</exception>
        public static byte[] Decrypt(byte[] key, byte[] iv, byte[] aad, byte[] cipherText, byte[] authTag)
        {
#if NET
            using var gcm =
                new System.Security.Cryptography.AesGcm(key, System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize);
#elif NETSTANDARD2_1
            using var gcm = new System.Security.Cryptography.AesGcm(key);
#endif

            var plaintext = new byte[cipherText.Length];

            gcm.Decrypt(nonce: iv, ciphertext: cipherText, tag: authTag, plaintext: plaintext, associatedData: aad);

            return plaintext;
        }
    }
}
#endif