using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Jose.keys;

namespace Jose
{
    public class RsaKeyManagement : IKeyManagement
    {
        private readonly bool useRsaOaepPadding; //true for RSA-OAEP, false for RSA-PKCS#1 v1.5

        public RsaKeyManagement(bool useRsaOaepPadding)
        {
            this.useRsaOaepPadding = useRsaOaepPadding;
        }

        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var cek = Arrays.Random(cekSizeBits);

            return new byte[][] { cek, this.WrapKey(cek, key, header) };
        }

        public byte[] WrapKey(byte[] cek, object key, IDictionary<string, object> header)
        {
#if NET40
            var publicKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return publicKey.Encrypt(cek, useRsaOaepPadding);
#elif NET461
            if (key is CngKey cngKey)
            {
                var publicKey = new RSACng(cngKey);

                var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                                  RSAEncryptionPadding.Pkcs1;

                return publicKey.Encrypt(cek, padding);
            }

            else if (key is RSACryptoServiceProvider rsaKey)
            {
                return rsaKey.Encrypt(cek, useRsaOaepPadding);
            }

            else if (key is RSA rsa)
            {
                var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                                  RSAEncryptionPadding.Pkcs1;

                return rsa.Encrypt(cek, padding);
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of either CngKey, RSACryptoServiceProvider or RSA types.");

#elif NETSTANDARD
            var publicKey = Ensure.Type<RSA>(key, "RsaKeyManagement alg expects key to be of RSA type.");

            var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                              RSAEncryptionPadding.Pkcs1;

            return publicKey.Encrypt(cek, padding);
#endif
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
#if NET40
            var privateKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return privateKey.Decrypt(encryptedCek, useRsaOaepPadding);
#elif NET461
            if (key is CngKey cngKey)
            {
                var privateKey = new RSACng(cngKey);

                var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                                  RSAEncryptionPadding.Pkcs1;

                return privateKey.Decrypt(encryptedCek, padding);
            }

            else if (key is RSACryptoServiceProvider rsaKey)
            {
                return rsaKey.Decrypt(encryptedCek, useRsaOaepPadding);
            }

            else if (key is RSA rsa)
            {
                var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                                  RSAEncryptionPadding.Pkcs1;

                return rsa.Decrypt(encryptedCek, padding);
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of either CngKey, RSACryptoServiceProvider or RSA types.");
#elif NETSTANDARD
            var privateKey = Ensure.Type<RSA>(key, "RsaKeyManagement algorithm expects key to be of RSA type.");

            var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                              RSAEncryptionPadding.Pkcs1;

            return privateKey.Decrypt(encryptedCek, padding);
#endif
        }
    }
}