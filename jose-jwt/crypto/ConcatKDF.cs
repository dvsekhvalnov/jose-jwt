using System;
using System.Security.Cryptography;
using Jose.native;
using Microsoft.Win32.SafeHandles;

namespace Jose
{
    public static class ConcatKDF
    {
        public static byte[] DeriveKey(CngKey externalPubKey, CngKey privateKey, int keyBitLength, byte[] algorithmId, byte[] partyVInfo, byte[] partyUInfo, byte[] suppPubInfo)
        {
#if NET40 || NET461 || NET472 || NETSTANDARD2_1
            using (var cng = new ECDiffieHellmanCng(privateKey))
            {
                using (SafeNCryptSecretHandle hSecretAgreement = cng.DeriveSecretAgreementHandle(externalPubKey))
                {
                    using (var algIdBuffer = new NCrypt.NCryptBuffer(NCrypt.KDF_ALGORITHMID, algorithmId))
                    using (var pviBuffer = new NCrypt.NCryptBuffer(NCrypt.KDF_PARTYVINFO, partyVInfo))
                    using (var pvuBuffer = new NCrypt.NCryptBuffer(NCrypt.KDF_PARTYUINFO, partyUInfo))
                    using (var spiBuffer = new NCrypt.NCryptBuffer(NCrypt.KDF_SUPPPUBINFO, suppPubInfo))
                    {
                        using (var parameters = new NCrypt.NCryptBufferDesc(algIdBuffer, pviBuffer, pvuBuffer, spiBuffer))
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
        
        public static byte[] DeriveKeyNonCng(ECDiffieHellman externalPubKey, ECDiffieHellman privateKey, int keyBitLength, byte[] algorithmId, byte[] partyVInfo, byte[] partyUInfo, byte[] suppPubInfo)
        {
            // Concat KDF, as defined in Section 5.8.1 of [NIST.800-56A]
            // reps = ceil( keydatalen / hashlen )
            // K(i) = H(counter || Z || OtherInfo)
            // DerivedKeyingMaterial = K(1) || K(2) || … || K(reps-1) || K_Last
            // So knowing that:
            // - jose-jwt supports a maximum keydatalen of 256
            // - and hashlen=256
            // then reps will always be 1
            const int reps = 1;

            var secretPrepend = Arrays.IntToBytes(reps);
            var secretAppend = Arrays.Concat(
                algorithmId,
                partyUInfo,
                partyVInfo,
                suppPubInfo
            );
            
            return Arrays.LeftmostBits(privateKey.DeriveKeyFromHash(
                externalPubKey.PublicKey,
                HashAlgorithmName.SHA256,
                secretPrepend,
                secretAppend), keyBitLength);
        }
    }
}