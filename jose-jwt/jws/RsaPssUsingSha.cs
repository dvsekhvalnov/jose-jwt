using System;
using System.Security.Cryptography;
using Jose.keys;

namespace Jose
{
    public class RsaPssUsingSha : IJwsAlgorithm
    {
        private readonly int saltSize;

        public RsaPssUsingSha(int saltSize)
        {
            this.saltSize = saltSize;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
#if NET40
            if (key is CngKey cngKey)
            {
                try
                {
                    return RsaPss.Sign(securedInput, cngKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    throw new JoseException("Unable to sign content.", e);
                }
            }
            else if (key is RSACryptoServiceProvider rsaKey)
            {
                //This is for backward compatibility only with 2.x
                //To be removed in 3.x
                var privateKey = RsaKey.New(rsaKey.ExportParameters(true));

                try
                {
                    return RsaPss.Sign(securedInput, privateKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    throw new JoseException("Unable to sign content.", e);
                }
            }

            throw new ArgumentException("RsaUsingSha with PSS padding alg expects key to be of CngKey type.");

#elif NET461 || NET472
            if (key is CngKey cngKey)
            {
                try
                {
                    return RsaPss.Sign(securedInput, cngKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    throw new JoseException("Unable to sign content.", e);
                }
            }
            else if (key is RSACryptoServiceProvider rsaKey)
            {
                //This is for backward compatibility only with 2.x
                //To be removed in 3.x
                var privateKey = RsaKey.New(rsaKey.ExportParameters(true));

                try
                {
                    return RsaPss.Sign(securedInput, privateKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    throw new JoseException("Unable to sign content.", e);
                }
            }
            else if (key is RSA rsa)
            {
                return rsa.SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pss);
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.RSA)
                {
                     return jwk.RsaKey().SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pss);
                }
            }

            throw new ArgumentException("RsaUsingSha with PSS padding alg expects key to be of either CngKey or RSA types or Jwk type with kty='RSA'");

#elif NETSTANDARD || NET
            if (key is RSA rsa)
            {
                return rsa.SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pss);
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.RSA)
                {
                     return jwk.RsaKey().SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pss);                    
                }
            }

            throw new ArgumentException("RsaUsingSha with PSS padding alg expects key to be of either RSA type or Jwk type with kty='RSA'");
#endif
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
#if NET40
            if (key is CngKey cngKey)
            {
                try
                {
                    return RsaPss.Verify(securedInput, signature, cngKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    return false;
                }
            }
            else if (key is RSACryptoServiceProvider rsaKey)
            {
                //This is for backward compatibility only with 2.x
                //To be removed in 3.x
                var publicKey = RsaKey.New(rsaKey.ExportParameters(false));

                try
                {
                    return RsaPss.Verify(securedInput, signature, publicKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    return false;
                }
            }

            throw new ArgumentException("RsaUsingSha with PSS padding alg expects key to be of CngKey type.");

#elif NET461 || NET472
            if (key is CngKey cngKey)
            {
                try
                {
                    return RsaPss.Verify(securedInput, signature, cngKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    return false;
                }
            }
            else if (key is RSACryptoServiceProvider rsaKey)
            {
                //This is for backward compatibility only with 2.x
                //To be removed in 3.x
                var publicKey = RsaKey.New(rsaKey.ExportParameters(false));

                try
                {
                    return RsaPss.Verify(securedInput, signature, publicKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    return false;
                }
            }
            else if (key is RSA rsa)
            {
                return rsa.VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pss);
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.RSA)
                {
                    return jwk.RsaKey().VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pss);
                }
            }

            throw new ArgumentException("RsaUsingSha with PSS padding alg expects key to be of either CngKey or RSA types or Jwk type with kty='RSA'");

#elif NETSTANDARD || NET
            if (key is RSA rsa)
            {
                return rsa.VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pss);
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.RSA)
                {
                    return jwk.RsaKey().VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pss);
                }
            }  
            
            throw new ArgumentException("RsaUsingSha with PSS padding alg expects key to be of either RSA type or Jwk type with kty='RSA'");
#endif
        }

#if NETSTANDARD || NET461 || NET472 || NET
        private HashAlgorithmName HashAlgorithm
        {
            get
            {
                switch (saltSize)
                {
                    case 32:
                        return HashAlgorithmName.SHA256;
                    case 48:
                        return HashAlgorithmName.SHA384;
                    case 64:
                        return HashAlgorithmName.SHA512;
                    default:
                        throw new ArgumentException(string.Format("Unsupported salt size: '{0} bytes'", saltSize));
                }
            }
        }
#endif

        private CngAlgorithm Hash
        {
            get
            {
                switch (saltSize)
                {
                    case 32:
                        return CngAlgorithm.Sha256;
                    case 48:
                        return CngAlgorithm.Sha384;
                    case 64:
                        return CngAlgorithm.Sha512;
                    default:
                        throw new ArgumentException(string.Format("Unsupported salt size: '{0} bytes'", saltSize));
                }
            }
        }
    }
}