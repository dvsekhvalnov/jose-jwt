using System;
using System.Security.Cryptography;

namespace Jose.keys
{
#if NET472 || NETSTANDARD2_1 || NET
    public class EcdhKey
    {
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

        /// <summary>
        /// Creates an AsymmetricAlgorithm Elliptic Curve Key ECDiffieHellman agreement from given (x,y) curve point - public part
        /// and optional d - private part
        /// </summary>
        /// <param name="x">x coordinate of curve point</param>
        /// <param name="y">y coordinate of curve point</param>
        /// <param name="d">optional private part</param>
        /// <returns>ECDiffieHellman for given (x,y) and d</returns>
        public static ECDiffieHellman New(byte[] x, byte[] y, byte[] d = null, CngKeyUsages usage = CngKeyUsages.Signing)
        {
            if (x.Length != y.Length)
            {
                throw new ArgumentException("X and Y must be the same size");
            }

            if (d != null && x.Length != d.Length)
            {
                throw new ArgumentException("X, Y, and D must be the same size");
            }

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
                Q = new ECPoint { X = x, Y = y },
                Curve = curve
            };

            if (d != null)
            {
                parameters.D = d;
            }

            return ECDiffieHellman.Create(parameters);
        }

        public static ECDiffieHellman FromPublic(ECDsa key)
        {
            var ecdh = ECDiffieHellman.Create();
            ecdh.ImportParameters(key.ExportParameters(false));

            return ecdh;
        }

        public static ECDiffieHellman FromPrivate(ECDsa key)
        {
            var ecdh = ECDiffieHellman.Create();
            ecdh.ImportParameters(key.ExportParameters(true));

            return ecdh;
        }

        public static EcdhKey Generate(ECDiffieHellman receiverPubKey)
        {
            ECCurve curve = receiverPubKey.ExportParameters(false).Curve;
            ECDiffieHellman ecdh = ECDiffieHellman.Create(curve);
    
            return new EcdhKey { key = ecdh };
        }

        public static EcdhKey Export(ECDiffieHellman _key, bool isPrivate = true)
        {
            // Assuming you're just copying the key reference. If you need to actually "export" or clone the key, you'd do that here.
            return new EcdhKey { key = _key, isPrivate = isPrivate };
        }

        public string Curve()
        {
            ECParameters parameters = key.ExportParameters(false);
            ECCurve curve = parameters.Curve;

            // Check OID values to determine curve
            if (curve.Oid.FriendlyName == "nistP256" || ECCurve.NamedCurves.nistP256.Oid.Value == curve.Oid.Value)
            {
                return "P-256";
            }

            if (curve.Oid.FriendlyName == "nistP384" || ECCurve.NamedCurves.nistP384.Oid.Value == curve.Oid.Value)
            {
                return "P-384";
            }

            if (curve.Oid.FriendlyName == "nistP521" || ECCurve.NamedCurves.nistP521.Oid.Value == curve.Oid.Value)
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
#endif
}
