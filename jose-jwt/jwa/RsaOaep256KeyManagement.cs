using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Jose.keys;

namespace Jose
{
    public class RsaOaep256KeyManagement : IKeyManagement
    {
        private readonly int hashSizeBits;

        public RsaOaep256KeyManagement(int hashSizeBits)
        {
            this.hashSizeBits = hashSizeBits;
        }

        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var cek = Arrays.Random(cekSizeBits);

            return new byte[][] { cek, this.WrapKey(cek, key, header) };
        }

        public byte[] WrapKey(byte[] cek, object key, IDictionary<string, object> header)
        {
#if NET40
            if (key is CngKey cngKey)
            {
                return RsaOaep.Encrypt(cek, cngKey, CngAlgorithmHash());
            }
            else if (key is RSACryptoServiceProvider rsaKey)
            {
                //This is for backward compatibility only with 2.x
                //To be removed in 3.x
                var publicKey = RsaKey.New(rsaKey.ExportParameters(false));

                return RsaOaep.Encrypt(cek, publicKey, CngAlgorithmHash());
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of CngKey or RSACryptoServiceProvider types.");

#elif NET461 || NET472
            if (key is CngKey cngKey)
            {
                return RsaOaep.Encrypt(cek, cngKey, CngAlgorithmHash());
            }

            else if (key is RSACryptoServiceProvider rsaKey)
            {
                //This is for backward compatibility only with 2.x
                //To be removed in 3.x
                var publicKey = RsaKey.New(rsaKey.ExportParameters(false));

                return RsaOaep.Encrypt(cek, publicKey, CngAlgorithmHash());
            }
            else if (key is RSA rsa)
            {
                return rsa.Encrypt(cek, OaepPadding());
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.RSA)
                {
                    return jwk.RsaKey().Encrypt(cek, OaepPadding());
                }
            }
            
            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of CngKey, RSACryptoServiceProvider, RSA types or Jwk type with kty='rsa'.");


#elif NETSTANDARD
            if (key is RSA rsa)
            {
                return rsa.Encrypt(cek, OaepPadding());
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.RSA)
                {
                    return jwk.RsaKey().Encrypt(cek, OaepPadding());
                }
            }
            
            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of RSA types or Jwk type with kty='rsa'.");
#endif

        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
#if NET40
            if (key is CngKey cngKey)
            {
                return RsaOaep.Decrypt(encryptedCek, cngKey, CngAlgorithmHash());
            }
            else if (key is RSACryptoServiceProvider rsaKey)
            {
                //This is for backward compatibility only with 2.x
                //To be removed in 3.x
                var privateKey = RsaKey.New(rsaKey.ExportParameters(true));

                return RsaOaep.Decrypt(encryptedCek, privateKey, CngAlgorithmHash());
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of CngKey type.");

#elif NET461 || NET472
            if (key is CngKey cngKey)
            {
                return RsaOaep.Decrypt(encryptedCek, cngKey, CngAlgorithmHash());
            }
            else if (key is RSACryptoServiceProvider rsaKey)
            {
                //This is for backward compatibility only with 2.x
                //To be removed in 3.x
                var privateKey = RsaKey.New(rsaKey.ExportParameters(true));

                return RsaOaep.Decrypt(encryptedCek, privateKey, CngAlgorithmHash());
            }
            else if (key is RSA rsa)
            {
                return rsa.Decrypt(encryptedCek, OaepPadding());
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.RSA)
                {
                    return jwk.RsaKey().Decrypt(encryptedCek, OaepPadding());
                }
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of CngKey, RSACryptoServiceProvider, RSA types or Jwk type with kty='rsa'.");

#elif NETSTANDARD
            if (key is RSA rsa)
            {
                return rsa.Decrypt(encryptedCek, OaepPadding());
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.RSA)
                {
                    return jwk.RsaKey().Decrypt(encryptedCek, OaepPadding());
                }
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of RSA type or Jwk type with kty='rsa'.");
#endif
        }

        private CngAlgorithm CngAlgorithmHash()
        {
            switch (hashSizeBits)
            {
                case 256:
                    return CngAlgorithm.Sha256;

                case 384:
                    return CngAlgorithm.Sha384;

                case 512:
                    return CngAlgorithm.Sha512;

                default:
                    throw new ArgumentException(string.Format("Unsupported hash size: {0} bits.", hashSizeBits));
            }
        }

        private RSAEncryptionPadding OaepPadding()
        {
            switch (hashSizeBits)
            {
                case 256:
                    return RSAEncryptionPadding.OaepSHA256;

                case 384:
                    return RSAEncryptionPadding.OaepSHA384;

                case 512:
                    return RSAEncryptionPadding.OaepSHA512;

                default:
                    throw new ArgumentException(string.Format("Unsupported hash size: {0} bits.", hashSizeBits));
            }
        }
    }
}