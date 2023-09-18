using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Jose.keys;

namespace Jose
{
    public class EcdhKeyManagement : IKeyManagement
    {
        private readonly string algIdHeader;

        public EcdhKeyManagement(bool isDirectAgreement)
        {
            algIdHeader = isDirectAgreement ? "enc" : "alg";
        }

        public virtual byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var cek = NewKey(cekSizeBits, key, header);
            var encryptedCek = Wrap(cek, key);

            return new[] { cek, encryptedCek };
        }

        public virtual byte[] WrapKey(byte[] cek, object key, IDictionary<string, object> header)
        {
            throw new JoseException("(Direct) ECDH-ES key management cannot use existing CEK.");
        }

        private byte[] NewKey(int keyLength, object key, IDictionary<string, object> header)
        {
            ECDiffieHellman receiverPubKey = null;

            if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.EC)
                {
                    receiverPubKey = jwk.EcDiffieHellmanKey();
                }
            }

            receiverPubKey ??= Ensure.Type<ECDiffieHellman>(key, "EcdhKeyManagement alg expects key to be of ECDiffieHellman or Jwk types with kty='EC'.");

            ECDiffieHellman ephemeral = ECDiffieHellman.Create(receiverPubKey.KeyExchangeAlgorithm);
            var ephemeralParameters = ephemeral.ExportParameters(false);

            IDictionary<string, object> epk = new Dictionary<string, object>();
            epk["kty"] = "EC";
            epk["x"] = Base64Url.Encode(ephemeralParameters.Q.X);
            epk["y"] = Base64Url.Encode(ephemeralParameters.Q.Y);
            epk["crv"] = Jwk.CurveToName(ephemeralParameters.Curve);

            header["epk"] = epk;

            return DeriveKey(header, keyLength, receiverPubKey, ephemeral);
        }

        public virtual byte[] Wrap(byte[] cek, object key)
        {
            return Arrays.Empty;
        }

        public virtual byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            ECDiffieHellman privateKey = null;

            if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.EC)
                {
                    privateKey = jwk.EcDiffieHellmanKey();
                }
            }

            privateKey = privateKey ?? Ensure.Type<ECDiffieHellman>(key, "EcdhKeyManagement alg expects key to be of ECDiffieHellman or Jwk types with kty='EC'.");            

            Ensure.Contains(header, new[] { "epk" }, "EcdhKeyManagement algorithm expects 'epk' key param in JWT header, but was not found");
            Ensure.Contains(header, new[] { algIdHeader }, "EcdhKeyManagement algorithm expects 'enc' header to be present in JWT header, but was not found");

            var epk = (IDictionary<string, object>)header["epk"];

            Ensure.Contains(epk, new[] { "x", "y", "crv" }, "EcdhKeyManagement algorithm expects 'epk' key to contain 'x','y' and 'crv' fields.");

            var x = Base64Url.Decode((string)epk["x"]);
            var y = Base64Url.Decode((string)epk["y"]);

            var externalPublicKey = CreateEcDiffieHellman(Jwk.NameToCurve((string)epk["crv"]), x, y, null);

            return DeriveKey(header, cekSizeBits, externalPublicKey, privateKey);
        }
        
        public static ECDiffieHellman CreateEcDiffieHellman(ECCurve curve, byte[] x, byte[] y, byte[] d)
        {
            var privateParameters = new ECParameters
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = x,
                    Y = y
                }
            };

            if (d != null)
            {
                privateParameters.D = d;
            }

            return ECDiffieHellman.Create(privateParameters);
        }

        private byte[] DeriveKey(IDictionary<string, object> header, int cekSizeBits, ECDiffieHellman externalPublicKey, ECDiffieHellman privateKey)
        {
            byte[] enc = Encoding.UTF8.GetBytes((string)header[algIdHeader]);
            byte[] apv = header.ContainsKey("apv") ? Base64Url.Decode((string)header["apv"]) : Arrays.Empty;
            byte[] apu = header.ContainsKey("apu") ? Base64Url.Decode((string)header["apu"]) : Arrays.Empty;

            byte[] algorithmId = Arrays.Concat(Arrays.IntToBytes(enc.Length), enc);
            byte[] partyUInfo = Arrays.Concat(Arrays.IntToBytes(apu.Length), apu);
            byte[] partyVInfo = Arrays.Concat(Arrays.IntToBytes(apv.Length), apv);
            byte[] suppPubInfo = Arrays.IntToBytes(cekSizeBits);

            return ConcatKDF.DeriveKeyNonCng(externalPublicKey, privateKey, cekSizeBits, algorithmId, partyVInfo, partyUInfo, suppPubInfo);
        }       
    }
}