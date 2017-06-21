using System;
using System.Security.Cryptography;
using Jose;

namespace Security.Cryptography
{
    public class RsaKey
    {
        public static readonly byte[] BCRYPT_RSAPUBLIC_MAGIC = BitConverter.GetBytes(0x31415352);
        public static readonly byte[] BCRYPT_RSAPRIVATE_MAGIC = BitConverter.GetBytes(0x32415352);
        
         
        public static CngKey New(RSAParameters parameters)
        {
            return New(parameters.Exponent, parameters.Modulus, parameters.P, parameters.Q);
        }

        public static CngKey New(byte[] exponent, byte[] modulus, byte[] p=null, byte[] q=null)
        {
            bool pubOnly = (p == null) || (q == null);

            byte[] magic = pubOnly ? BCRYPT_RSAPUBLIC_MAGIC : BCRYPT_RSAPRIVATE_MAGIC;
            byte[] bitLength = BitConverter.GetBytes(modulus.Length * 8);
            byte[] expLength = BitConverter.GetBytes(exponent.Length);
            byte[] modLength = BitConverter.GetBytes(modulus.Length);
            byte[] prime1Length = pubOnly ? BitConverter.GetBytes(0x00000000) : BitConverter.GetBytes(p.Length);
            byte[] prime2Length = pubOnly ? BitConverter.GetBytes(0x00000000) : BitConverter.GetBytes(q.Length);

            byte[] blob = Arrays.Concat(magic, bitLength, expLength, modLength, prime1Length, prime2Length, exponent, modulus, p, q);

            var format = pubOnly ? CngKeyBlobFormat.GenericPublicBlob : CngKeyBlobFormat.GenericPrivateBlob;

            return CngKey.Import(blob, format);
        }
    }
}