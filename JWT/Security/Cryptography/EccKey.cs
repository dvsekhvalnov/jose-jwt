using System;
using System.Security.Cryptography;
using Jose;

namespace Security.Cryptography
{
    public class EccKey
    {
        public static readonly byte[] BCRYPT_ECDSA_PUBLIC_P256_MAGIC = BitConverter.GetBytes(0x31534345);
        public static readonly byte[] BCRYPT_ECDSA_PRIVATE_P256_MAGIC = BitConverter.GetBytes(0x32534345);
        public static readonly byte[] BCRYPT_ECDSA_PUBLIC_P384_MAGIC = BitConverter.GetBytes(0x33534345);
        public static readonly byte[] BCRYPT_ECDSA_PRIVATE_P384_MAGIC = BitConverter.GetBytes(0x34534345);
        public static readonly byte[] BCRYPT_ECDSA_PUBLIC_P521_MAGIC = BitConverter.GetBytes(0x35534345);
        public static readonly byte[] BCRYPT_ECDSA_PRIVATE_P521_MAGIC = BitConverter.GetBytes(0x36534345);           

        public static CngKey New(byte[] x, byte[] y, byte[] d=null)
        {
            if (x.Length != y.Length)
                throw new ArgumentException("X,Y and D must be same size");

            if(d!=null && x.Length!=d.Length)
                throw new ArgumentException("X,Y and D must be same size");

            int partSize = x.Length; 

            byte[] magic;
            
            if(partSize==32)
                magic = (d == null) ? BCRYPT_ECDSA_PUBLIC_P256_MAGIC : BCRYPT_ECDSA_PRIVATE_P256_MAGIC; 
            else if(partSize==48)
                magic = (d == null) ? BCRYPT_ECDSA_PUBLIC_P384_MAGIC : BCRYPT_ECDSA_PRIVATE_P384_MAGIC; 
            else if(partSize==66)
                magic = (d == null) ? BCRYPT_ECDSA_PUBLIC_P521_MAGIC : BCRYPT_ECDSA_PRIVATE_P521_MAGIC; 
            else
                throw new ArgumentException("Size of X,Y or D must equal to 32, 48 or 66 bytes");

            byte[] partLength = BitConverter.GetBytes(partSize);

            CngKeyBlobFormat blobType;
            byte[] blob;
            
            if(d==null)
            {
                blob = Arrays.Concat(magic, partLength, x, y);    
                blobType = CngKeyBlobFormat.EccPublicBlob;
            }
            else
            {
                blob = Arrays.Concat(magic, partLength, x, y, d);    
                blobType = CngKeyBlobFormat.EccPrivateBlob;               ;
            }

            return CngKey.Import(blob, blobType);
        }
    }
}