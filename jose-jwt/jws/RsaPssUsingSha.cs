using System;
using System.Security.Cryptography;
using Security.Cryptography;

namespace Jose
{
    public class RsaPssUsingSha : IJwsAlgorithm
    {
        private int saltSize;

        public RsaPssUsingSha(int saltSize)
        {
            this.saltSize = saltSize;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
    #if NET40
            if (key is CngKey)
            {
                var privateKey = (CngKey)key;

                try
                {
                    return RsaPss.Sign(securedInput, privateKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    throw new JoseException("Unable to sign content.", e);    
                }
            }

            else if (key is RSACryptoServiceProvider)
            {
                //This is for backward compatibility only with 2.x 
                //To be removed in 3.x 
                var privateKey = RsaKey.New(((RSACryptoServiceProvider)key).ExportParameters(true));

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
    
    #elif NET461
            if (key is CngKey)
            {
                var privateKey = (CngKey)key;

                try
                {
                    return RsaPss.Sign(securedInput, privateKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    throw new JoseException("Unable to sign content.", e);    
                }
            }

            if (key is RSACryptoServiceProvider)
            {
                //This is for backward compatibility only with 2.x 
                //To be removed in 3.x 
                var privateKey = RsaKey.New(((RSACryptoServiceProvider)key).ExportParameters(true));

                try
                {
                    return RsaPss.Sign(securedInput, privateKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    throw new JoseException("Unable to sign content.", e);    
                }
            }

            if (key is RSA)
            {
                var privateKey = (RSA) key;
                return privateKey.SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pss);
            }

            throw new ArgumentException("RsaUsingSha with PSS padding alg expects key to be of either CngKey or RSA types.");

    #elif NETSTANDARD1_4
            var privateKey = Ensure.Type<RSA>(key, "RsaUsingSha with PSS padding alg expects key to be of RSA type.");

            return privateKey.SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pss);
    #endif
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
    #if NET40
            if (key is CngKey)
            {
                var publicKey = (CngKey)key;

                try
                {
                    return RsaPss.Verify(securedInput, signature, publicKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    return false;
                }
            }

            if (key is RSACryptoServiceProvider)
            {
                //This is for backward compatibility only with 2.x 
                //To be removed in 3.x 
                var publicKey = RsaKey.New(((RSACryptoServiceProvider)key).ExportParameters(false));

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

    #elif NET461
            if (key is CngKey)
            {
                var publicKey = (CngKey)key;

                try
                {
                    return RsaPss.Verify(securedInput, signature, publicKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    return false;
                }
            }

            if (key is RSACryptoServiceProvider)
            {
                //This is for backward compatibility only with 2.x 
                //To be removed in 3.x 
                var publicKey = RsaKey.New(((RSACryptoServiceProvider)key).ExportParameters(false));

                try
                {
                    return RsaPss.Verify(securedInput, signature, publicKey, Hash, saltSize);
                }
                catch (CryptographicException e)
                {
                    return false;
                }
            }

            if (key is RSA)
            {
                var publicKey = (RSA) key;

                return publicKey.VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pss);
            }

            throw new ArgumentException("RsaUsingSha with PSS padding alg expects key to be of either CngKey or RSA types.");

    #elif NETSTANDARD1_4
            var publicKey = Ensure.Type<RSA>(key, "RsaUsingSha with PSS padding alg expects key to be of RSA type.");
            return publicKey.VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pss);
    #endif
        }

    #if NETSTANDARD1_4 || NET461
        private HashAlgorithmName HashAlgorithm
        {
            get
            {
                if (saltSize == 32)
                    return HashAlgorithmName.SHA256;
                if (saltSize == 48)
                    return HashAlgorithmName.SHA384;
                if (saltSize == 64)
                    return HashAlgorithmName.SHA512;

                throw new ArgumentException(string.Format("Unsupported salt size: '{0} bytes'", saltSize));
            }
        }
    #endif

        private CngAlgorithm Hash
        {
            get
            {
                if (saltSize == 32)
                    return CngAlgorithm.Sha256;
                if (saltSize == 48)
                    return CngAlgorithm.Sha384;
                if (saltSize == 64)
                    return CngAlgorithm.Sha512;

                throw new ArgumentException(string.Format("Unsupported salt size: '{0} bytes'", saltSize));
            }
        }

    }
}