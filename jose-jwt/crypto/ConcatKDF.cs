using System;
using System.Security.Cryptography;
using Jose.native;
using Microsoft.Win32.SafeHandles;

namespace Jose
{
    public class ConcatKDF
    {
        public static byte[] DeriveKey(CngKey externalPubKey, CngKey privateKey, int keyBitLength, byte[] algorithmId, byte[] partyVInfo, byte[] partyUInfo, byte[] suppPubInfo)
        {
#if NET40 || NET461
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
        #elif NETSTANDARD1_4
            throw new NotImplementedException("not yet");
        #endif
        }
    }
}