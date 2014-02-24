using System;
using System.Security.Cryptography;

namespace Jose
{
    public class RsaUsingSha : IJwsAlgorithm
    {
        private string hashMethod;

        public RsaUsingSha(string hashMethod)
        {
            this.hashMethod = hashMethod;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
            using (var sha = HashAlgorithm)
            {
                var privateKey = Ensure.Type<AsymmetricAlgorithm>(key, "RsaUsingSha alg expects key to be of AsymmetricAlgorithm type."); 

                var pkcs1 = new RSAPKCS1SignatureFormatter(privateKey);
                pkcs1.SetHashAlgorithm(hashMethod);

                return pkcs1.CreateSignature(sha.ComputeHash(securedInput));                    
            } 
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
            using (var sha = HashAlgorithm)
            {
                var publicKey = Ensure.Type<AsymmetricAlgorithm>(key, "RsaUsingSha alg expects key to be of AsymmetricAlgorithm type."); 
                
                byte[] hash = sha.ComputeHash(securedInput);

                var pkcs1 = new RSAPKCS1SignatureDeformatter(publicKey);
                pkcs1.SetHashAlgorithm(hashMethod);

                return pkcs1.VerifySignature(hash, signature);
            }
        }

        private HashAlgorithm HashAlgorithm
        {
            get
            {
                if (hashMethod.Equals("SHA256"))
                    return new SHA256Managed();
                if (hashMethod.Equals("SHA384"))
                    return new SHA384Managed();
                if (hashMethod.Equals("SHA512"))
                    return new SHA512Managed();

                throw new ArgumentException("Unsupported hashing algorithm: '{0}'", hashMethod);
            }
        }
    }
}