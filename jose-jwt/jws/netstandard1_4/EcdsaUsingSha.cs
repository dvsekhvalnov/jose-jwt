#if NETSTANDARD || NET461

using System;
using System.Security.Cryptography;

namespace Jose.netstandard1_4
{
    public class EcdsaUsingSha : IJwsAlgorithm
    {
        private readonly int keySize;

        public EcdsaUsingSha(int keySize)
        {
            this.keySize = keySize;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
            try
            {
                if (key is CngKey cngKey)
                {
                    Ensure.BitSize(cngKey.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, cngKey.KeySize));

                    using (var signer = new ECDsaCng(cngKey))
                    {
                        return signer.SignData(securedInput, Hash);
                    }
                }
                else if (key is ECDsa ecDsa)
                {
                    Ensure.BitSize(ecDsa.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, ecDsa.KeySize));

                    return ecDsa.SignData(securedInput, Hash);
                }

                throw new ArgumentException("EcdsaUsingSha algorithm expects key to be of either CngKey or ECDsa types.");
            }
            catch (CryptographicException e)
            {
                throw new JoseException("Unable to sign content.", e);
            }
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
            try
            {
                if (key is CngKey cngKey)
                {
                    Ensure.BitSize(cngKey.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, cngKey.KeySize));

                    using (var signer = new ECDsaCng(cngKey))
                    {
                        return signer.VerifyData(securedInput, signature, Hash);
                    }
                }
                else if (key is ECDsa ecDsa)
                {
                    Ensure.BitSize(ecDsa.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, ecDsa.KeySize));

                    return ecDsa.VerifyData(securedInput, signature, Hash);
                }

                throw new ArgumentException("EcdsaUsingSha algorithm expects key to be of either CngKey or ECDsa types.");
            }
            catch (CryptographicException e)
            {
                return false;
            }
        }

        protected HashAlgorithmName Hash
        {
            get
            {
                switch (keySize)
                {
                    case 256:
                        return HashAlgorithmName.SHA256;
                    case 384:
                        return HashAlgorithmName.SHA384;
                    case 521:
                        return HashAlgorithmName.SHA512;
                    default:
                        throw new ArgumentException(string.Format("Unsupported key size: '{0} bytes'", keySize));
                }
            }
        }
    }
}
#endif