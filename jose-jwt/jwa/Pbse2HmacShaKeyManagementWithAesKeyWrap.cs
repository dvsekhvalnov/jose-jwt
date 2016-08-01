using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Jose
{
    public class Pbse2HmacShaKeyManagementWithAesKeyWrap : IKeyManagement
    {
        private AesKeyWrapManagement aesKW;
        private int keyLengthBits;

        public Pbse2HmacShaKeyManagementWithAesKeyWrap(int keyLengthBits, AesKeyWrapManagement aesKw)
        {
            aesKW = aesKw;
            this.keyLengthBits = keyLengthBits;
        }

        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var sharedPassphrase = Ensure.Type<string>(key, "Pbse2HmacShaKeyManagementWithAesKeyWrap management algorithm expectes key to be string.");

            byte[] sharedKey = Encoding.UTF8.GetBytes(sharedPassphrase);
            byte[] algId = Encoding.UTF8.GetBytes((string)header["alg"]);

            int iterationCount = 8192;
            byte[] saltInput = Arrays.Random(96); //12 bytes

            header["p2c"] = iterationCount;
            header["p2s"] = Base64Url.Encode(saltInput);

            byte[] salt = Arrays.Concat(algId, Arrays.Zero, saltInput);

            byte[] kek;

            using (var prf = PRF)
            {
                kek = PBKDF2.DeriveKey(sharedKey, salt, iterationCount, keyLengthBits, prf);
            }

            return aesKW.WrapNewKey(cekSizeBits, kek, header);
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            var sharedPassphrase = Ensure.Type<string>(key, "Pbse2HmacShaKeyManagementWithAesKeyWrap management algorithm expectes key to be string.");

            byte[] sharedKey = Encoding.UTF8.GetBytes(sharedPassphrase);

            Ensure.Contains(header, new[] { "p2c" }, "Pbse2HmacShaKeyManagementWithAesKeyWrap algorithm expects 'p2c' param in JWT header, but was not found");
            Ensure.Contains(header, new[] { "p2s" }, "Pbse2HmacShaKeyManagementWithAesKeyWrap algorithm expects 'p2s' param in JWT header, but was not found");

            byte[] algId=Encoding.UTF8.GetBytes((string) header["alg"]);
            int iterationCount= Convert.ToInt32(header["p2c"]);
            byte[] saltInput = Base64Url.Decode((string) header["p2s"]);

            byte[] salt = Arrays.Concat(algId, Arrays.Zero, saltInput);

            byte[] kek; 

            using(var prf=PRF)
            {                
                kek=PBKDF2.DeriveKey(sharedKey, salt, iterationCount, keyLengthBits, prf);
            }

            return aesKW.Unwrap(encryptedCek, kek, cekSizeBits, header);
        }

        private HMAC PRF
        {
            get
            {
                if (keyLengthBits == 128)
                    return new HMACSHA256();
                if (keyLengthBits == 192)
                    return new HMACSHA384();
                if (keyLengthBits == 256)
                    return new HMACSHA512();

                throw new ArgumentException(string.Format("Unsupported key size: '{0}'", keyLengthBits));
            }
        }
    }
}