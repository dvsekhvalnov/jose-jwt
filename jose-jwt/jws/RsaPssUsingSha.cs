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
            var privateKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaUsingSha with PSS padding alg expects key to be of RSACryptoServiceProvider type.");

            try
            {
                return RsaPss.Sign(securedInput, RsaKey.New(privateKey.ExportParameters(true)), Hash, saltSize);
            }
            catch (CryptographicException e)
            {
                throw new JoseException("Unable to sign content.", e);    
            }
#elif NETSTANDARD1_4
            var privateKey = Ensure.Type<RSA>(key, "RsaUsingSha with PSS padding alg expects key to be of RSA type.");
            return privateKey.SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pss);
#endif
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
#if NET40
            var publicKey = Ensure.Type<RSACryptoServiceProvider>(key,
                "RsaUsingSha with PSS padding alg expects key to be of RSACryptoServiceProvider type.");

            try
            {
                return RsaPss.Verify(securedInput, signature, RsaKey.New(publicKey.ExportParameters(false)), Hash,
                    saltSize);
            }
            catch (CryptographicException e)
            {
                return false;
            }

#elif NETSTANDARD1_4
            var publicKey = Ensure.Type<RSA>(key, "RsaUsingSha with PSS padding alg expects key to be of RSA type.");
            return publicKey.VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pss);
#endif
        }

#if NETSTANDARD1_4
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