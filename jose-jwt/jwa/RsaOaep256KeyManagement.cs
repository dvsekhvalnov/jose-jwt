using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Jose.keys;

namespace Jose
{
    public class RsaOaep256KeyManagement : IKeyManagement
    {
        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var cek = Arrays.Random(cekSizeBits);

            return new byte[][] { cek, this.WrapKey(cek, key, header) };
        }
        
        public byte[] WrapKey(byte[] cek, object key, IDictionary<string, object> header)
        {            
        #if NET40
            if (key is CngKey)
            {
                var publicKey = (CngKey)key;

                return RsaOaep.Encrypt(cek, publicKey, CngAlgorithm.Sha256);
            }

            if (key is RSACryptoServiceProvider)
            {
                //This is for backward compatibility only with 2.x 
                //To be removed in 3.x 
                var publicKey = RsaKey.New(((RSACryptoServiceProvider)key).ExportParameters(false));

                return RsaOaep.Encrypt(cek, publicKey, CngAlgorithm.Sha256);
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of CngKey or RSACryptoServiceProvider types.");

        #elif NET461 || NET472
            if (key is CngKey)
            {
                var publicKey = (CngKey) key;

                return RsaOaep.Encrypt(cek, publicKey, CngAlgorithm.Sha256);
            }

            if (key is RSACryptoServiceProvider)
            {
                //This is for backward compatibility only with 2.x 
                //To be removed in 3.x 
                var publicKey = RsaKey.New(((RSACryptoServiceProvider) key).ExportParameters(false));

                return RsaOaep.Encrypt(cek, publicKey, CngAlgorithm.Sha256);
            }

            if (key is RSA)
            {
	            var publicKey = (RSA) key;

                return publicKey.Encrypt(cek, RSAEncryptionPadding.OaepSHA256);
            }

            if (key is Jwk)
            {
                var publicKey = (Jwk)key;

                if (publicKey.Kty == Jwk.KeyTypes.RSA)
                {
                    return publicKey.RsaKey().Encrypt(cek, RSAEncryptionPadding.OaepSHA256);
                }
            }
            
            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of CngKey, RSACryptoServiceProvider, RSA types or JWK type with kty='rsa'.");


        #elif NETSTANDARD
            if (key is RSA)
            {
	            var publicKey = (RSA) key;

                return publicKey.Encrypt(cek, RSAEncryptionPadding.OaepSHA256);
            }

            if (key is JWK)
            {
                var publicKey = (JWK)key;

                if (publicKey.Kty == JWK.KeyTypes.RSA)
                {
                    return publicKey.RsaKey().Encrypt(cek, RSAEncryptionPadding.OaepSHA256);
                }
            }
            
            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of RSA types or JWK type with kty='rsa'.");
        #endif

        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
        #if NET40
            if(key is RSACryptoServiceProvider)
            {
                //This is for backward compatibility only with 2.x 
                //To be removed in 3.x 
                var privateKey = RsaKey.New(((RSACryptoServiceProvider) key).ExportParameters(true));

                return RsaOaep.Decrypt(encryptedCek, privateKey, CngAlgorithm.Sha256);

            }

            if(key is CngKey)
            {
                var privateKey = (CngKey) key;

	            return RsaOaep.Decrypt(encryptedCek, privateKey, CngAlgorithm.Sha256);
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of CngKey type.");

         #elif NET461 || NET472
            if (key is CngKey)
            {
                var privateKey = (CngKey) key;

	            return RsaOaep.Decrypt(encryptedCek, privateKey, CngAlgorithm.Sha256);
            }

            if (key is RSACryptoServiceProvider)
            {
                //This is for backward compatibility only with 2.x 
                //To be removed in 3.x 
                var privateKey = RsaKey.New(((RSACryptoServiceProvider) key).ExportParameters(true));

                return RsaOaep.Decrypt(encryptedCek, privateKey, CngAlgorithm.Sha256);
            }

            if (key is RSA)
            {
                var privateKey = (RSA) key;

                return privateKey.Decrypt(encryptedCek, RSAEncryptionPadding.OaepSHA256);				
            }

            if (key is Jwk)
            {
                var privateKey = (Jwk)key;

                if (privateKey.Kty == Jwk.KeyTypes.RSA)
                {
                    return privateKey.RsaKey().Decrypt(encryptedCek, RSAEncryptionPadding.OaepSHA256);
                }
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of CngKey, RSACryptoServiceProvider, RSA types or JWK type with kty='rsa'.");

#elif NETSTANDARD
            if (key is RSA)
            {
                var privateKey = (RSA) key;

                return privateKey.Decrypt(encryptedCek, RSAEncryptionPadding.OaepSHA256);				
            }

            if (key is JWK)
            {
                var privateKey = (JWK)key;

                if (privateKey.Kty == JWK.KeyTypes.RSA)
                {
                    return privateKey.RsaKey().Decrypt(encryptedCek, RSAEncryptionPadding.OaepSHA256);
                }
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of RSA type or JWK type with kty='rsa'.");
#endif
        }
    }
}