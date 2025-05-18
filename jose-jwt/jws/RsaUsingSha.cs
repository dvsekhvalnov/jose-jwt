using System;
using System.Security.Cryptography;

namespace Jose
{
    public class RsaUsingSha : IJwsAlgorithm
    {
        private readonly string hashMethod;

        public RsaUsingSha(string hashMethod)
        {
            this.hashMethod = hashMethod;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
#if NET40
            var privateKey = Ensure.Type<RSA>(key, "RsaUsingSha alg expects key to be of AsymmetricAlgorithm type.");

            using (var sha = HashAlgorithm)
            {
                var pkcs1 = new RSAPKCS1SignatureFormatter(privateKey);
                pkcs1.SetHashAlgorithm(hashMethod);

                return pkcs1.CreateSignature(sha.ComputeHash(securedInput));
            }

#elif NET461_OR_GREATER || NETSTANDARD || NET
            if (key is RSA rsa)
            {
                return rsa.SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pkcs1);
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.RSA)
                {
                    return jwk.RsaKey().SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pkcs1);
                }
            }

            throw new ArgumentException("RsaUsingSha alg expects key to be of RSA type or Jwk type with kty='RSA'");
#endif
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
#if NET40
            using (var sha = HashAlgorithm)
            {
                var publicKey = Ensure.Type<AsymmetricAlgorithm>(key, "RsaUsingSha alg expects key to be of AsymmetricAlgorithm type.");

                byte[] hash = sha.ComputeHash(securedInput);
                var pkcs1 = new RSAPKCS1SignatureDeformatter(publicKey);
                pkcs1.SetHashAlgorithm(hashMethod);

                return pkcs1.VerifySignature(hash, signature);
            }
#elif NET461_OR_GREATER || NETSTANDARD || NET
            if (key is RSA rsa)
            {
                return rsa.VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pkcs1);
            }
            else if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.RSA)
                {
                    return jwk.RsaKey().VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pkcs1);
                }
            }

            throw new ArgumentException("RsaUsingSha alg expects key to be of RSA type or Jwk type with kty='rsa'");
#endif
        }

#if NET40
        private HashAlgorithm HashAlgorithm
        {
            get
            {
                if (hashMethod.Equals("SHA256"))
                    return new SHA256CryptoServiceProvider();
                else if (hashMethod.Equals("SHA384"))
                    return new SHA384CryptoServiceProvider();
                else if (hashMethod.Equals("SHA512"))
                    return new SHA512CryptoServiceProvider();
                else
                    throw new ArgumentException("Unsupported hashing algorithm: '{0}'", hashMethod);
            }
        }
#elif NET461_OR_GREATER || NETSTANDARD || NET
        private HashAlgorithmName HashAlgorithm
        {
            get
            {
                if (hashMethod.Equals("SHA256"))
                    return HashAlgorithmName.SHA256;
                else if (hashMethod.Equals("SHA384"))
                    return HashAlgorithmName.SHA384;
                else if (hashMethod.Equals("SHA512"))
                    return HashAlgorithmName.SHA512;
                else
                    throw new ArgumentException("Unsupported hashing algorithm: '{0}'", hashMethod);
            }
        }
#endif
    }
}