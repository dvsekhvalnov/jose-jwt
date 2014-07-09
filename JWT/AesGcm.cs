using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Jose.native;

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
            IntPtr hAlg = OpenAlgorithmProvider(BCrypt.BCRYPT_AES_ALGORITHM, BCrypt.MS_PRIMITIVE_PROVIDER, BCrypt.BCRYPT_CHAIN_MODE_GCM);
            IntPtr hKey, keyDataBuffer = ImportKey(hAlg, key, out hKey);

            byte[] cipher;
            byte[] tag = new byte[MaxAuthTagSize(hAlg)];

            var authInfo = new BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, aad, tag);
            using (authInfo)
            {
                byte[] ivData = new byte[tag.Length];

                int cipherSize = 0;

                uint status = BCrypt.BCryptEncrypt(hKey, plainText, plainText.Length, ref authInfo, ivData, ivData.Length, null, 0, ref cipherSize, 0x0);

                if (status != BCrypt.ERROR_SUCCESS)
                    throw new CryptographicException(string.Format("BCrypt.BCryptEncrypt() (get size) failed with status code:{0}", status));

                cipher = new byte[cipherSize];

                status = BCrypt.BCryptEncrypt(hKey, plainText, plainText.Length, ref authInfo, ivData, ivData.Length,
                                              cipher, cipher.Length, ref cipherSize, 0x0);

                if (status != BCrypt.ERROR_SUCCESS)
                    throw new CryptographicException(string.Format("BCrypt.BCryptEncrypt() failed with status code:{0}", status));

                Marshal.Copy(authInfo.pbTag, tag, 0, authInfo.cbTag);
            }

            BCrypt.BCryptDestroyKey(hKey);
            Marshal.FreeHGlobal(keyDataBuffer);
            BCrypt.BCryptCloseAlgorithmProvider(hAlg, 0x0);

            return new[] {cipher, tag};
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
            IntPtr hAlg = OpenAlgorithmProvider(BCrypt.BCRYPT_AES_ALGORITHM, BCrypt.MS_PRIMITIVE_PROVIDER, BCrypt.BCRYPT_CHAIN_MODE_GCM);
            IntPtr hKey,keyDataBuffer = ImportKey(hAlg, key, out hKey);

            byte[] plainText;

            var authInfo = new BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, aad, authTag);
            using (authInfo)
            {
                byte[] ivData = new byte[MaxAuthTagSize(hAlg)];

                int plainTextSize = 0;

                uint status = BCrypt.BCryptDecrypt(hKey, cipherText, cipherText.Length, ref authInfo, ivData, ivData.Length, null, 0, ref plainTextSize, 0x0);

                if (status != BCrypt.ERROR_SUCCESS)
                    throw new CryptographicException(string.Format("BCrypt.BCryptDecrypt() (get size) failed with status code: {0}", status));

                plainText = new byte[plainTextSize];

                status = BCrypt.BCryptDecrypt(hKey, cipherText, cipherText.Length, ref authInfo, ivData, ivData.Length, plainText, plainText.Length, ref plainTextSize, 0x0);

                if(status==BCrypt.STATUS_AUTH_TAG_MISMATCH)
                    throw new CryptographicException("BCrypt.BCryptDecrypt(): authentication tag mismatch");

                if (status != BCrypt.ERROR_SUCCESS)
                    throw new CryptographicException(string.Format("BCrypt.BCryptDecrypt() failed with status code:{0}", status));                
            }

            BCrypt.BCryptDestroyKey(hKey);
            Marshal.FreeHGlobal(keyDataBuffer);
            BCrypt.BCryptCloseAlgorithmProvider(hAlg, 0x0);

            return plainText;
        }

        private static int MaxAuthTagSize(IntPtr hAlg)
        {
            byte[] tagLengthsValue = GetProperty(hAlg, BCrypt.BCRYPT_AUTH_TAG_LENGTH);

            return BitConverter.ToInt32(new[] { tagLengthsValue[4], tagLengthsValue[5], tagLengthsValue[6], tagLengthsValue[7] }, 0);
        }

        private static IntPtr OpenAlgorithmProvider(string alg, string provider, string chainingMode)
        {
            IntPtr hAlg = IntPtr.Zero;

            uint status = BCrypt.BCryptOpenAlgorithmProvider(out hAlg, alg, provider, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}", status));

            byte[] chainMode = Encoding.Unicode.GetBytes(chainingMode);
            status = BCrypt.BCryptSetAlgorithmProperty(hAlg, BCrypt.BCRYPT_CHAINING_MODE, chainMode, chainMode.Length, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed with status code:{0}", status));

            return hAlg;
        }

        private static IntPtr ImportKey(IntPtr hAlg, byte[] key, out IntPtr hKey)
        {
            byte[] objLength = GetProperty(hAlg, BCrypt.BCRYPT_OBJECT_LENGTH);

            int keyDataSize = BitConverter.ToInt32(objLength, 0);

            IntPtr keyDataBuffer = Marshal.AllocHGlobal(keyDataSize);

            byte[] keyBlob = Arrays.Concat(BCrypt.BCRYPT_KEY_DATA_BLOB_MAGIC, BitConverter.GetBytes(0x1), BitConverter.GetBytes(key.Length), key);

            uint status = BCrypt.BCryptImportKey(hAlg, IntPtr.Zero, BCrypt.BCRYPT_KEY_DATA_BLOB, out hKey, keyDataBuffer, keyDataSize, keyBlob, keyBlob.Length, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptImportKey() failed with status code:{0}", status));

            return keyDataBuffer;
        }


        private static byte[] GetProperty(IntPtr hAlg, string name)
        {
            int size = 0;

            uint status = BCrypt.BCryptGetProperty(hAlg, name, null, 0, ref size, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptGetProperty() (get size) failed with status code:{0}", status));

            byte[] value = new byte[size];

            status=BCrypt.BCryptGetProperty(hAlg, name, value, value.Length, ref size, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptGetProperty() failed with status code:{0}", status));

            return value;
        }
    }
}