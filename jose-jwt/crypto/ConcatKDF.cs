using System;
using System.Security.Cryptography;
using Jose.native;
using Microsoft.Win32.SafeHandles;

namespace Jose
{
    public static class ConcatKDF
    {
        // Microsoft CNG implementation is unusable on NIST-384 and NISP-521 curves due to broken key derivation
        // https://stackoverflow.com/questions/10879658/existing-implementations-for-nist-sp-800-56a-concatenation-single-step-key-deriv
        public static byte[] DeriveKey(CngKey externalPubKey, CngKey privateKey, int keyBitLength, byte[] algorithmId, byte[] partyVInfo, byte[] partyUInfo, byte[] suppPubInfo)
        {
#if NET40 || NET461 || NET472 || NETSTANDARD2_1 || NET
            using (var cng = new ECDiffieHellmanCng(privateKey))
            {
                using (SafeNCryptSecretHandle hSecretAgreement = cng.DeriveSecretAgreementHandle(externalPubKey))
                {
                    using (var algIdBuffer = new NCrypt.NCryptBuffer(NCrypt.KDF_ALGORITHMID, algorithmId))
                    using (var pviBuffer = new NCrypt.NCryptBuffer(NCrypt.KDF_PARTYVINFO, partyVInfo))
                    using (var pvuBuffer = new NCrypt.NCryptBuffer(NCrypt.KDF_PARTYUINFO, partyUInfo))
                    using (var spiBuffer = new NCrypt.NCryptBuffer(NCrypt.KDF_SUPPPUBINFO, suppPubInfo))
                    {
                        using (var parameters = new NCrypt.NCryptBufferDesc(algIdBuffer, pvuBuffer, pviBuffer, spiBuffer))
                        {
                            uint derivedSecretByteSize;
                            uint status = NCrypt.NCryptDeriveKey(hSecretAgreement, "SP800_56A_CONCAT", parameters, null, 0, out derivedSecretByteSize, 0);

                            if (status != BCrypt.ERROR_SUCCESS)
                                throw new CryptographicException(string.Format("NCrypt.NCryptDeriveKey() failed with status code:{0}", status));

                            var secretKey = new byte[derivedSecretByteSize];

                            status = NCrypt.NCryptDeriveKey(hSecretAgreement, "SP800_56A_CONCAT", parameters, secretKey, derivedSecretByteSize, out derivedSecretByteSize, 0);

                            if (status != BCrypt.ERROR_SUCCESS)
                                throw new CryptographicException(string.Format("NCrypt.NCryptDeriveKey() failed with status code:{0}", status));

                            return Arrays.LeftmostBits(secretKey, keyBitLength);
                        }
                    }
                }
            }
#else
            throw new NotImplementedException("not yet");
#endif
        }
#if NET472 || NETSTANDARD2_1 || NET
        public static byte[] DeriveEcdhKey(ECDiffieHellman externalPubKey, ECDiffieHellman privateKey, int keyBitLength, byte[] algorithmId, byte[] partyVInfo, byte[] partyUInfo, byte[] suppPubInfo)
        {
            // Concat KDF, as defined in Section 5.8.1 of [NIST.800-56A]
            // reps = ceil( keydatalen / hashlen )
            // K(i) = H(counter || Z || OtherInfo)
            // DerivedKeyingMaterial = K(1) || K(2) || … || K(reps-1) || K_Last
            int reps = (int)Math.Ceiling(keyBitLength / (double)256);

            byte[][] K = new byte[reps][];

            var otherInfo = Arrays.Concat(
                    algorithmId,
                    partyUInfo,
                    partyVInfo,
                    suppPubInfo
                );

            for (int c = 1; c <= reps; c++)
            {
                byte[] keyMaterial = privateKey.DeriveKeyFromHash(
                    externalPubKey.PublicKey,
                    HashAlgorithmName.SHA256,
                    Arrays.IntToBytes(c),
                    otherInfo);

                K[c - 1] = keyMaterial;

            }

            return Arrays.LeftmostBits(Arrays.Concat(K), keyBitLength);
        }
#endif
    }
}