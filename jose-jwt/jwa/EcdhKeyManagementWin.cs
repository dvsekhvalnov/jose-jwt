using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Jose.keys;

namespace Jose
{
    public class EcdhKeyManagementWin : IKeyManagement
    {
        private readonly IKeyManagement ecdhKeyManagementUnix;
        private readonly string algIdHeader;

        public EcdhKeyManagementWin(bool isDirectAgreement, IKeyManagement ecdhKeyManagementUnix)
        {
            this.ecdhKeyManagementUnix = ecdhKeyManagementUnix;
            algIdHeader = isDirectAgreement ? "enc" : "alg";
        }

        public virtual byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
#if NET472 || NETSTANDARD2_1 || NET
            if (key is ECDiffieHellman || key is ECDsa || key is Jwk)
            {
                return ecdhKeyManagementUnix.WrapNewKey(cekSizeBits, key, header);
            }
#endif            
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
            CngKey recieverPubKey = null;

            if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.EC)
                {
                    recieverPubKey = jwk.CngKey(CngKeyUsages.KeyAgreement);
                }
            }

            recieverPubKey = recieverPubKey ?? Ensure.Type<CngKey>(key, "EcdhKeyManagement alg expects key to be of CngKey or Jwk types with kty='EC'.");
            
            EccKey ephemeral = EccKey.Generate(recieverPubKey);

            IDictionary<string, object> epk = new Dictionary<string, object>();
            epk["kty"] = "EC";
            epk["x"] = Base64Url.Encode(ephemeral.X);
            epk["y"] = Base64Url.Encode(ephemeral.Y);
            epk["crv"] = ephemeral.Curve();

            header["epk"] = epk;

            return DeriveKey(header, keyLength, recieverPubKey, ephemeral.Key);
        }

        public virtual byte[] Wrap(byte[] cek, object key)
        {
            return Arrays.Empty;
        }

        public virtual byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
#if NET472 || NETSTANDARD2_1 || NET
            if (key is ECDiffieHellman || key is ECDsa  || key is Jwk)
            {
                return ecdhKeyManagementUnix.Unwrap(encryptedCek, key, cekSizeBits, header);
            }
#endif            
            CngKey privateKey = null;

            if (key is Jwk jwk)
            {
                if (jwk.Kty == Jwk.KeyTypes.EC)
                {
                    privateKey = jwk.CngKey(CngKeyUsages.KeyAgreement);
                }
            }

            privateKey = privateKey ?? Ensure.Type<CngKey>(key, "EcdhKeyManagement alg expects key to be of CngKey or Jwk types with kty='EC'.");            

            Ensure.Contains(header, new[] { "epk" }, "EcdhKeyManagement algorithm expects 'epk' key param in JWT header, but was not found");
            Ensure.Contains(header, new[] { algIdHeader }, "EcdhKeyManagement algorithm expects 'enc' header to be present in JWT header, but was not found");

            var epk = (IDictionary<string, object>)header["epk"];

            Ensure.Contains(epk, new[] { "x", "y", "crv" }, "EcdhKeyManagement algorithm expects 'epk' key to contain 'x','y' and 'crv' fields.");

            var x = Base64Url.Decode((string)epk["x"]);
            var y = Base64Url.Decode((string)epk["y"]);

            var externalPublicKey = EccKey.New(x, y, usage: CngKeyUsages.KeyAgreement);

            return DeriveKey(header, cekSizeBits, externalPublicKey, privateKey);
        }

        private byte[] DeriveKey(IDictionary<string, object> header, int cekSizeBits, CngKey externalPublicKey, CngKey privateKey)
        {
            byte[] enc = Encoding.UTF8.GetBytes((string)header[algIdHeader]);
            byte[] apv = header.ContainsKey("apv") ? Base64Url.Decode((string)header["apv"]) : Arrays.Empty;
            byte[] apu = header.ContainsKey("apu") ? Base64Url.Decode((string)header["apu"]) : Arrays.Empty;

            byte[] algorithmId = Arrays.Concat(Arrays.IntToBytes(enc.Length), enc);
            byte[] partyUInfo = Arrays.Concat(Arrays.IntToBytes(apu.Length), apu);
            byte[] partyVInfo = Arrays.Concat(Arrays.IntToBytes(apv.Length), apv);
            byte[] suppPubInfo = Arrays.IntToBytes(cekSizeBits);

            return ConcatKDF.DeriveKey(externalPublicKey, privateKey, cekSizeBits, algorithmId, partyVInfo, partyUInfo, suppPubInfo);
        }      
    }
}