using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Security.Cryptography;

namespace Jose
{
    public class RsaKeyManagement:IKeyManagement
    {        
        private bool useRsaOaepPadding; //true for RSA-OAEP, false for RSA-PKCS#1 v1.5
        
        public RsaKeyManagement(bool useRsaOaepPadding)
        {
            this.useRsaOaepPadding = useRsaOaepPadding;
        }

        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var cek = Arrays.Random(cekSizeBits);

#if NET40
            var publicKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return new[] { cek, publicKey.Encrypt(cek, useRsaOaepPadding) };
#elif NET461
            if (key is CngKey)
            {
                var publicKey = new RSACng((CngKey) key);

                var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                                  RSAEncryptionPadding.Pkcs1;

                return new[] { cek, publicKey.Encrypt(cek, padding) };
            }

            if (key is RSACryptoServiceProvider)
            {
                var publicKey = (RSACryptoServiceProvider) key;

                return new[] { cek, publicKey.Encrypt(cek, useRsaOaepPadding) };
            }

            if (key is RSA)
            {
                var publicKey = (RSA) key;

                var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                                  RSAEncryptionPadding.Pkcs1;

                return new[] { cek, publicKey.Encrypt(cek, padding) };
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of either CngKey, RSACryptoServiceProvider or RSA types.");

#elif NETSTANDARD1_4
            var publicKey = Ensure.Type<RSA>(key, "RsaKeyManagement alg expects key to be of RSA type.");

            var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                              RSAEncryptionPadding.Pkcs1;

            return new[] { cek, publicKey.Encrypt(cek, padding) };
#endif
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
#if NET40
            var privateKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return privateKey.Decrypt(encryptedCek, useRsaOaepPadding);
#elif NET461
            if (key is CngKey)
            {
                var privateKey = new RSACng((CngKey)key);

                var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                                  RSAEncryptionPadding.Pkcs1;

                return privateKey.Decrypt(encryptedCek, padding);
            }

            if (key is RSACryptoServiceProvider)
            {
                var privateKey = (RSACryptoServiceProvider) key;

                return privateKey.Decrypt(encryptedCek, useRsaOaepPadding);
            }

            if (key is RSA)
            {
                var privateKey = (RSA) key;

                var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                                  RSAEncryptionPadding.Pkcs1;

                return privateKey.Decrypt(encryptedCek, padding);
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of either CngKey, RSACryptoServiceProvider or RSA types.");
#elif NETSTANDARD1_4
            var privateKey = Ensure.Type<RSA>(key, "RsaKeyManagement algorithm expects key to be of RSA type.");

            var padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                              RSAEncryptionPadding.Pkcs1;

            return privateKey.Decrypt(encryptedCek, padding);
#endif
        }
    }
}