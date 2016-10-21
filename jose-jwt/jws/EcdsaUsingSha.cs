#if NET40
using System;
using System.Security.Cryptography;

namespace Jose
{
    public class EcdsaUsingSha : IJwsAlgorithm
    {
        private int keySize;

        public EcdsaUsingSha(int keySize)
        {
            this.keySize = keySize;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
            var privateKey = Ensure.Type<CngKey>(key, "EcdsaUsingSha alg expects key to be of CngKey type.");

            Ensure.BitSize(privateKey.KeySize, keySize, string.Format("ECDSA algorithm expected key of size {0} bits, but was given {1} bits", keySize, privateKey.KeySize));

            try
            {
                using (var signer = new ECDsaCng(privateKey))
                {
                    signer.HashAlgorithm = Hash;

                    return signer.SignData(securedInput);
                }
            }
            catch (CryptographicException e)
            {
                throw new JoseException("Unable to sign content.", e);    
            }
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
            var publicKey = Ensure.Type<CngKey>(key, "EcdsaUsingSha alg expects key to be of CngKey type.");

            Ensure.BitSize(publicKey.KeySize, keySize, string.Format("ECDSA algorithm expected key of size {0} bits, but was given {1} bits", keySize, publicKey.KeySize));

            try
            {
                using (var signer = new ECDsaCng(publicKey))
                {
                    signer.HashAlgorithm = Hash;
                
                    return signer.VerifyData(securedInput, signature);
                }
            }
            catch (CryptographicException e)
            {
                return false;
            }
        }

        protected CngAlgorithm Hash
        {
            get
            {
                if (keySize == 256)
                    return CngAlgorithm.Sha256;
                if (keySize == 384)
                    return CngAlgorithm.Sha384;
                if (keySize == 521)
                    return CngAlgorithm.Sha512;

                throw new ArgumentException(string.Format("Unsupported key size: '{0} bytes'", keySize));
            }
        }
    }
}
#endif