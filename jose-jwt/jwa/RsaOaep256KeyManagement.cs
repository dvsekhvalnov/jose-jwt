using System.Collections.Generic;
using System.Security.Cryptography;
using Security.Cryptography;

namespace Jose
{
    public class RsaOaep256KeyManagement : IKeyManagement
    {
        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var cek = Arrays.Random(cekSizeBits);

        #if NET40
            var publicKey = Ensure.Type<CngKey>(key, "RsaOaep256KeyManagement alg expects key to be of CngKey type.");

            return new[] {cek, RsaOaep.Encrypt(cek, publicKey, CngAlgorithm.Sha256)};

        #elif NETSTANDARD1_4
            var publicKey = Ensure.Type<RSA>(key, "RsaKeyManagement alg expects key to be of RSA type.");

            return new[] { cek, publicKey.Encrypt(cek, RSAEncryptionPadding.OaepSHA256) };
        #endif

        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
        #if NET40
            var privateKey = Ensure.Type<CngKey>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return RsaOaep.Decrypt(encryptedCek, privateKey, CngAlgorithm.Sha256);

        #elif NETSTANDARD1_4
            var privateKey = Ensure.Type<RSA>(key, "RsaKeyManagement alg expects key to be of RSA type.");

            return privateKey.Decrypt(encryptedCek, RSAEncryptionPadding.OaepSHA256);
        #endif
        }
    }
}