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

        public static readonly byte[] BCRYPT_ECDH_PUBLIC_P256_MAGIC  = BitConverter.GetBytes(0x314B4345);
        public static readonly byte[] BCRYPT_ECDH_PRIVATE_P256_MAGIC = BitConverter.GetBytes(0x324B4345);
        public static readonly byte[] BCRYPT_ECDH_PUBLIC_P384_MAGIC = BitConverter.GetBytes(0x334B4345);
        public static readonly byte[] BCRYPT_ECDH_PRIVATE_P384_MAGIC = BitConverter.GetBytes(0x344B4345);
        public static readonly byte[] BCRYPT_ECDH_PUBLIC_P521_MAGIC = BitConverter.GetBytes(0x354B4345);
        public static readonly byte[] BCRYPT_ECDH_PRIVATE_P521_MAGIC = BitConverter.GetBytes(0x364B4345);

        private CngKey key;

        private byte[] x;
        private byte[] y;
        private byte[] d;

        public byte[] X
        {
            get
            {
                if(x==null) ExportKey();

                return x;
            }
        }

        public byte[] Y
        {
            get 
            { 
                if(y==null) ExportKey();

                return y; 
            }
        }

        public byte[] D
        {
            get 
            { 
                if(d==null) ExportKey();

                return d; 
            }
        }

        public CngKey Key
        {
            get { return key;}
        }

        /// <summary>
        /// Creates CngKey Elliptic Curve Key from given (x,y) curve point - public part 
        /// and optional d - private part
        /// </summary>
        /// <param name="x">x coordinate of curve point</param>
        /// <param name="y">y coordinate of curve point</param>
        /// <param name="d">optional private part</param>
        /// <returns>CngKey for given (x,y) and d</returns>
        public static CngKey New(byte[] x, byte[] y, byte[] d=null, CngKeyUsages usage=CngKeyUsages.Signing)
        {
            if (x.Length != y.Length)
                throw new ArgumentException("X,Y and D must be same size");

            if(d!=null && x.Length!=d.Length)
                throw new ArgumentException("X,Y and D must be same size");

            if(usage!=CngKeyUsages.Signing && usage!=CngKeyUsages.KeyAgreement)
                throw new ArgumentException("Usage parameter expected to be set either 'CngKeyUsages.Signing' or 'CngKeyUsages.KeyAgreement");

            bool signing = usage == CngKeyUsages.Signing;

            int partSize = x.Length; 

            byte[] magic;

            if (partSize == 32)
            {
                magic = (d == null)
                            ? signing ? BCRYPT_ECDSA_PUBLIC_P256_MAGIC  : BCRYPT_ECDH_PUBLIC_P256_MAGIC
                            : signing ? BCRYPT_ECDSA_PRIVATE_P256_MAGIC : BCRYPT_ECDH_PRIVATE_P256_MAGIC;
            }
            else if (partSize == 48)
            {
                magic = (d == null)
                            ? signing ? BCRYPT_ECDSA_PUBLIC_P384_MAGIC  : BCRYPT_ECDH_PUBLIC_P384_MAGIC
                            : signing ? BCRYPT_ECDSA_PRIVATE_P384_MAGIC : BCRYPT_ECDH_PRIVATE_P384_MAGIC;
            }
            else if (partSize == 66)
            {
                magic = (d == null)
                            ? signing ? BCRYPT_ECDSA_PUBLIC_P521_MAGIC  : BCRYPT_ECDH_PUBLIC_P521_MAGIC
                            : signing ? BCRYPT_ECDSA_PRIVATE_P521_MAGIC : BCRYPT_ECDH_PRIVATE_P521_MAGIC;
            }
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

        public static EccKey Generate(CngKey receiverPubKey)
        {
            CngKey cngKey = CngKey.Create(receiverPubKey.Algorithm, null, new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport });

            return new EccKey {key = cngKey};
        }

        public static EccKey Export(CngKey _key)
        {
            return new EccKey { key = _key };
        }

        private void ExportKey()
        {
            byte[] blob = key.Export(CngKeyBlobFormat.EccPrivateBlob);
            byte[] length = new[] { blob[4], blob[5], blob[6], blob[7] };

            int partSize = BitConverter.ToInt32(length, 0);

            byte[][] keyParts = Arrays.Slice(Arrays.RightmostBits(blob, partSize * 24), partSize);

            x = keyParts[0];
            y = keyParts[1];
            d = keyParts[2];
        }
    }
}
