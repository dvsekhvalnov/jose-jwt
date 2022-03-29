using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Jose.keys;

namespace Jose
{
    public class RsaKeyManagement : IKeyManagement
    {        
        private bool useRsaOaepPadding; //true for RSA-OAEP, false for RSA-PKCS#1 v1.5
        
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
#elif NET461 || NET472
            if (key is CngKey)
            {
                return encrypt(cek, new RSACng((CngKey)key));
            }

            if (key is RSACryptoServiceProvider)
            {
                var publicKey = (RSACryptoServiceProvider) key;

                return publicKey.Encrypt(cek, useRsaOaepPadding);
            }

            if (key is RSA)
            {
                return encrypt(cek, (RSA)key);
            }

            if (key is Jwk)
            {
                var publicKey = (Jwk)key;

                if (publicKey.Kty == Jwk.KeyTypes.RSA)
                {
                    return encrypt(cek, publicKey.RsaKey());
                }
            }


            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of CngKey, RSACryptoServiceProvider, RSA types or Jwk type with kty='rsa'.");

#elif NETSTANDARD
            if (key is RSA)
            {
                return encrypt(cek, (RSA)key);
            }

            if (key is Jwk)
            {
                var publicKey = (Jwk)key;

                if (publicKey.Kty == Jwk.KeyTypes.RSA)
                {
                    return encrypt(cek, publicKey.RsaKey());
                }
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of RSA type or Jwk type with kty='rsa'.");
#endif
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
#if NET40
            var privateKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return privateKey.Decrypt(encryptedCek, useRsaOaepPadding);
#elif NET461 || NET472
            if (key is CngKey)
            {
                return decrypt(encryptedCek, new RSACng((CngKey)key));
            }

            if (key is RSACryptoServiceProvider)
            {
                var privateKey = (RSACryptoServiceProvider) key;

                return privateKey.Decrypt(encryptedCek, useRsaOaepPadding);
            }

            if (key is RSA)
            {
                return decrypt(encryptedCek, (RSA)key);
            }

            if (key is Jwk)
            {
                var publicKey = (Jwk)key;

                if (publicKey.Kty == Jwk.KeyTypes.RSA)
                {
                    return decrypt(encryptedCek, publicKey.RsaKey());
                }
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of CngKey, RSACryptoServiceProvider, RSA types or Jwk type with kty='rsa'.");

#elif NETSTANDARD
            if (key is RSA)
            {
                return decrypt(encryptedCek, (RSA)key); 
            }

            if (key is Jwk)
            {
                var privateKey = (Jwk)key;

                if (privateKey.Kty == Jwk.KeyTypes.RSA)
                {
                    return decrypt(encryptedCek, privateKey.RsaKey());
                }
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of RSA type or Jwk type with kty='rsa'.");
#endif        
        }

#if NET461 || NET472 || NETSTANDARD
        private byte[] decrypt(byte[] content, RSA privateKey)
        {
            RSAEncryptionPadding padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                                               RSAEncryptionPadding.Pkcs1;
            
            return privateKey.Decrypt(content, padding);
        }
        private byte[] encrypt(byte[] content, RSA publicKey)
        {
            RSAEncryptionPadding padding = useRsaOaepPadding ? RSAEncryptionPadding.OaepSHA1 :
                                                               RSAEncryptionPadding.Pkcs1;

            return publicKey.Encrypt(content, padding);
        }
#endif
    }
}
