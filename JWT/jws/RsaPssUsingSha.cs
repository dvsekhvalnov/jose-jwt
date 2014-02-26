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
            var privateKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaUsingSha with PSS padding alg expects key to be of RSACryptoServiceProvider type.");

            try
            {
                using (RSACng rsa = new RSACng())
                {
                    rsa.ImportParameters(privateKey.ExportParameters(true));
                    rsa.SignatureHashAlgorithm = Hash;
                    rsa.SignaturePaddingMode = AsymmetricPaddingMode.Pss;
                    rsa.SignatureSaltBytes = saltSize;

                    return rsa.SignData(securedInput);
                }
            }
            catch (CryptographicException e)
            {
                throw new JoseException("Unable to sign content.", e);    
            }
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
            var publicKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaUsingSha with PSS padding alg expects key to be of RSACryptoServiceProvider type.");

            try
            {
                using (RSACng rsa = new RSACng())
                {
                    rsa.ImportParameters(publicKey.ExportParameters(false));
                    rsa.SignatureHashAlgorithm = Hash;
                    rsa.SignaturePaddingMode=AsymmetricPaddingMode.Pss;
                    rsa.SignatureSaltBytes = saltSize;

                    return rsa.VerifyData(securedInput,signature);
                }
            }
            catch (CryptographicException e)
            {
                return false;
            }
        }

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