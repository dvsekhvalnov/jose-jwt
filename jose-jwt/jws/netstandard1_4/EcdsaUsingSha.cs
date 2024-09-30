#if NETSTANDARD || NET461 || NET472 || NET

using System;
using System.Runtime.Versioning;
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
#if NET
                if (OperatingSystem.IsWindows() && key is CngKey cngKey)
#else
                if (key is CngKey cngKey)
#endif
                {
                    return Sign(cngKey, securedInput);
                }
                else if (key is ECDsa ecDsa)
                {
                    return Sign(ecDsa, securedInput);
                }
                else if (key is Jwk jwk)
                {
                    if (jwk.Kty == Jwk.KeyTypes.EC)
                    {
#if NETSTANDARD || NET472 || NET
                        return Sign(jwk.ECDsaKey(), securedInput);
#else
                        return Sign(jwk.CngKey(), securedInput);
#endif
                    }
                }


                throw new ArgumentException("EcdsaUsingSha algorithm expects key to be of CngKey, ECDsa or Jwk types with kty='EC'.");
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
#if NET
                if (OperatingSystem.IsWindows() && key is CngKey cngKey)
#else
                if (key is CngKey cngKey)
#endif
                {
                    return Verify(cngKey, signature, securedInput);
                }
                else if (key is ECDsa ecDsa)
                {
                    return Verify(ecDsa, signature, securedInput);
                }
                else if (key is Jwk jwk)
                {
                    if (jwk.Kty == Jwk.KeyTypes.EC)
                    {
#if NETSTANDARD || NET472 || NET
                        return Verify(jwk.ECDsaKey(), signature, securedInput);
#else
                        return Verify(jwk.CngKey(), signature, securedInput);
#endif
                    }
                }

                throw new ArgumentException("EcdsaUsingSha algorithm expects key to be of CngKey, ECDsa or Jwk types with kty='EC'.");
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

        [SupportedOSPlatform("windows")]
        private byte[] Sign(CngKey privateKey, byte[] securedInput)
        {
            Ensure.BitSize(privateKey.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, privateKey.KeySize));

            using (var signer = new ECDsaCng(privateKey))
            {
                return signer.SignData(securedInput, Hash);
            }
        }

        private byte[] Sign(ECDsa privateKey, byte[] securedInput)
        {
            Ensure.BitSize(privateKey.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, privateKey.KeySize));

            return privateKey.SignData(securedInput, Hash);
        }

        [SupportedOSPlatform("windows")]
        private bool Verify(CngKey publicKey, byte[] signature, byte[] securedInput)
        {
            Ensure.BitSize(publicKey.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, publicKey.KeySize));

            using (var signer = new ECDsaCng(publicKey))
            {
                return signer.VerifyData(securedInput, signature, Hash);
            }
        }

        private bool Verify(ECDsa publicKey, byte[] signature, byte[] securedInput)
        {
            Ensure.BitSize(publicKey.KeySize, keySize, string.Format("EcdsaUsingSha algorithm expected key of size {0} bits, but was given {1} bits", keySize, publicKey.KeySize));

            return publicKey.VerifyData(securedInput, signature, Hash);
        }
    }
}
#endif