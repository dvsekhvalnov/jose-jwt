using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Jose;

namespace Jose.keys
{
    public class EccKey
    {
        public static readonly byte[] BCRYPT_ECDSA_PUBLIC_P256_MAGIC = BitConverter.GetBytes(0x31534345);
        public static readonly byte[] BCRYPT_ECDSA_PRIVATE_P256_MAGIC = BitConverter.GetBytes(0x32534345);
        public static readonly byte[] BCRYPT_ECDSA_PUBLIC_P384_MAGIC = BitConverter.GetBytes(0x33534345);
        public static readonly byte[] BCRYPT_ECDSA_PRIVATE_P384_MAGIC = BitConverter.GetBytes(0x34534345);
        public static readonly byte[] BCRYPT_ECDSA_PUBLIC_P521_MAGIC = BitConverter.GetBytes(0x35534345);
        public static readonly byte[] BCRYPT_ECDSA_PRIVATE_P521_MAGIC = BitConverter.GetBytes(0x36534345);

        public static readonly byte[] BCRYPT_ECDH_PUBLIC_P256_MAGIC = BitConverter.GetBytes(0x314B4345);
        public static readonly byte[] BCRYPT_ECDH_PRIVATE_P256_MAGIC = BitConverter.GetBytes(0x324B4345);
        public static readonly byte[] BCRYPT_ECDH_PUBLIC_P384_MAGIC = BitConverter.GetBytes(0x334B4345);
        public static readonly byte[] BCRYPT_ECDH_PRIVATE_P384_MAGIC = BitConverter.GetBytes(0x344B4345);
        public static readonly byte[] BCRYPT_ECDH_PUBLIC_P521_MAGIC = BitConverter.GetBytes(0x354B4345);
        public static readonly byte[] BCRYPT_ECDH_PRIVATE_P521_MAGIC = BitConverter.GetBytes(0x364B4345);

        private ECDiffieHellman key;
        private bool isPrivate = true;

        private byte[] x;
        private byte[] y;
        private byte[] d;

        public byte[] X
        {
            get
            {
                if (x == null) ExportKey();

                return x;
            }
        }

        public byte[] Y
        {
            get
            {
                if (y == null) ExportKey();

                return y;
            }
        }

        public byte[] D
        {
            get
            {
                if (d == null && isPrivate) ExportKey();

                return d;
            }
        }

        public ECDiffieHellman Key
        {
            get { return key; }
        }

        public static ECDiffieHellman New(byte[] x, byte[] y, byte[] d = null, CngKeyUsages usage = CngKeyUsages.Signing)
        {
            return New<ECDiffieHellman>(x, y, d);
        }

        /// <summary>
        /// Creates an AsymmetricAlgorithm Elliptic Curve Key (ECDiffieHellman or ECDsa) from given (x,y) curve point - public part
        /// and optional d - private part
        /// </summary>
        /// <param name="x">x coordinate of curve point</param>
        /// <param name="y">y coordinate of curve point</param>
        /// <param name="d">optional private part</param>
        /// <returns>CngKey for given (x,y) and d</returns>
        public static T New<T>(byte[] x, byte[] y, byte[] d = null) where T : AsymmetricAlgorithm
        {
            if (x.Length != y.Length)
                throw new ArgumentException("X and Y must be the same size");

            if (d != null && x.Length != d.Length)
                throw new ArgumentException("X, Y, and D must be the same size");

            ECCurve curve;
            int partSize = x.Length;

            if (partSize == 32)
            {
                curve = ECCurve.NamedCurves.nistP256;
            }
            else if (partSize == 48)
            {
                curve = ECCurve.NamedCurves.nistP384;
            }
            else if (partSize == 66)
            {
                curve = ECCurve.NamedCurves.nistP521;
            }
            else
            {
                throw new ArgumentException("Size of X, Y, or D must equal to 32, 48, or 66 bytes");
            }

            ECParameters parameters = new ECParameters
            {
                Q = new ECPoint
                {
                    X = x,
                    Y = y
                },
                Curve = curve
            };

            if (d != null)
            {
                parameters.D = d;
            }
            
            // If T is a ECDiffieHellman, we create an ECDiffieHellman object, otherwise we create a ECDsa object
            // If T is not a ECDiffieHellman or ECDsa, we throw an exception
            if (typeof(T) != typeof(ECDiffieHellman) && typeof(T) != typeof(ECDsa))
            {
                throw new ArgumentException("T must be ECDiffieHellman or ECDsa");
            }
            
            return typeof(T) == typeof(ECDiffieHellman) ? 
                ECDiffieHellman.Create(parameters) as T : 
                ECDsa.Create(parameters) as T;
        }

        public static EccKey Export(ECDiffieHellman _key, bool isPrivate = true)
        {
            // Assuming you're just copying the key reference. If you need to actually "export" or clone the key, you'd do that here.
            return new EccKey { key = _key, isPrivate = isPrivate };
        }

        public string Curve()
        {
            ECParameters parameters = key.ExportParameters(false);
            ECCurve curve = parameters.Curve;

            // Check OID values to determine curve
            if (curve.Oid.FriendlyName == "nistP256")
            {
                return "P-256";
            }

            if (curve.Oid.FriendlyName == "nistP384")
            {
                return "P-384";
            }

            if (curve.Oid.FriendlyName == "nistP521")
            {
                return "P-521";
            }

            throw new ArgumentException("Unknown curve type " + curve.Oid.FriendlyName);
        }

        private void ExportKey()
        {
            ECParameters parameters = key.ExportParameters(isPrivate);

            x = parameters.Q.X;
            y = parameters.Q.Y;

            if (isPrivate)
            {
                d = parameters.D;
            }
        }
    }
}
