using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Security.Cryptography;

namespace Jose
{
    public class RsaKeyManagement:IKeyManagement
    {        
        private bool useRsaOaepPadding; //true for RSA-OAEP, false for RSA-PKCS#1 v1.5
        private bool useSha256; //true for RSA-OAEP-256
        
        public RsaKeyManagement(bool useRsaOaepPadding, bool useSha256=false)
        {
            this.useRsaOaepPadding = useRsaOaepPadding;
            this.useSha256 = useSha256;
        }

        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {            
            var publicKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            var cek = Arrays.Random(cekSizeBits);

            return useSha256 ? new[] {cek, RsaOaep.Encrypt(cek, RsaKey.New(publicKey.ExportParameters(false)), CngAlgorithm.Sha256)} 
                             : new[] {cek, publicKey.Encrypt(cek, useRsaOaepPadding)};
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            var privateKey = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.");

            return useSha256 ? RsaOaep.Decrypt(encryptedCek, RsaKey.New(privateKey.ExportParameters(true)), CngAlgorithm.Sha256)
                             : privateKey.Decrypt(encryptedCek, useRsaOaepPadding);
        }
    }
}