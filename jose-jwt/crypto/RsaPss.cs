using System;
using System.Security.Cryptography;
using Jose.native;

namespace Jose
{
    public static class RsaPss
    {
        public static byte[] Sign(byte[] input, CngKey key, CngAlgorithm hash, int saltSize)
        {
            using (HashAlgorithm algo = HashAlgorithm(hash))
            {
                return SignHash(algo.ComputeHash(input), key, hash.Algorithm, saltSize);
            }
        }

        public static bool Verify(byte[] securedInput, byte[] signature, CngKey key, CngAlgorithm hash, int saltSize)
        {
            using (HashAlgorithm algo = HashAlgorithm(hash))
            {
                return VerifyHash(algo.ComputeHash(securedInput),signature, key, hash.Algorithm, saltSize);
            }
        }

        private static bool VerifyHash(byte[] hash, byte[] signature, CngKey key, string algorithm, int saltSize)
        {
            var paddingInfo = new BCrypt.BCRYPT_PSS_PADDING_INFO(algorithm, saltSize);

            uint status = NCrypt.NCryptVerifySignature(key.Handle, ref paddingInfo, hash, hash.Length, signature, signature.Length, BCrypt.BCRYPT_PAD_PSS);

            if (status == NCrypt.NTE_BAD_SIGNATURE) //honestly it always failing with NTE_INVALID_PARAMETER, but let's stick to public API
                return false;

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("NCrypt.NCryptSignHash() (signature size) failed with status code:{0}", status));

            return true;
        }

        private static byte[] SignHash(byte[] hash, CngKey key, string algorithm, int saltSize)
        {
            var paddingIndo=new BCrypt.BCRYPT_PSS_PADDING_INFO(algorithm, saltSize);

            uint size;
            uint status;

            status = NCrypt.NCryptSignHash(key.Handle, ref paddingIndo, hash, hash.Length, null, 0, out size,BCrypt.BCRYPT_PAD_PSS);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("NCrypt.NCryptSignHash() (signature size) failed with status code:{0}", status));

            byte[] signature=new byte[size];

            status = NCrypt.NCryptSignHash(key.Handle, ref paddingIndo, hash, hash.Length, signature, signature.Length, out size, BCrypt.BCRYPT_PAD_PSS);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("NCrypt.NCryptSignHash() failed with status code:{0}", status));

            return signature;
        }


        private static HashAlgorithm HashAlgorithm(CngAlgorithm hash)
        {
        #if NET40 || NET461
            if (hash == CngAlgorithm.Sha256)
                return new SHA256Cng();
            if (hash == CngAlgorithm.Sha384)
                return new SHA384Cng();
            if (hash == CngAlgorithm.Sha512)
                return new SHA512Cng();
            
            throw new ArgumentException(string.Format("RsaPss expects hash function to be SHA256, SHA384 or SHA512, but was given:{0}",hash));
            
        #elif NETSTANDARD1_4
            throw new NotImplementedException("not yet");
        #endif
        }
    }
}