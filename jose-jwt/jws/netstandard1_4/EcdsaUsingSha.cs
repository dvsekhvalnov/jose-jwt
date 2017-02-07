#if NETSTANDARD1_4 || NET461

using System;
using System.Security.Cryptography;

namespace Jose.netstandard1_4
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
            try
            {
                if (key is CngKey)
                {
                    var privateKey = (CngKey) key;

                    Ensure.BitSize(privateKey.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, privateKey.KeySize));

                    using (var signer = new ECDsaCng(privateKey))
                    {
                        return signer.SignData(securedInput, Hash);
                    }
                }
                if (key is ECDsa)
                {
                    var privateKey = (ECDsa) key;

                    Ensure.BitSize(privateKey.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, privateKey.KeySize));

                    return privateKey.SignData(securedInput, Hash);
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
                if (key is CngKey)
                {
                    var publicKey = (CngKey) key;

                    Ensure.BitSize(publicKey.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, publicKey.KeySize));

                    using (var signer = new ECDsaCng(publicKey))
                    {
                        return signer.VerifyData(securedInput, signature, Hash);
                    }
                }

                if (key is ECDsa)
                {
                    var publicKey = (ECDsa)key;

                    Ensure.BitSize(publicKey.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, publicKey.KeySize));

                    return publicKey.VerifyData(securedInput, signature, Hash);
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
                if (keySize == 256)
                    return HashAlgorithmName.SHA256;
                if (keySize == 384)
                    return HashAlgorithmName.SHA384;
                if (keySize == 521)
                    return HashAlgorithmName.SHA512;

                throw new ArgumentException(string.Format("Unsupported key size: '{0} bytes'", keySize));
            }
        }
    }
}
#endif