using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Jose;
using Jose.keys;
using Xunit;

namespace UnitTests
{
    public class ConcatKDFTest
    {
        [SkippableFact]
        public void Derive128BitKey()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
                "This requires CNG, which is Windows Only.");

            // https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23#appendix-C

            //given
            byte[] bob_x = Base64Url.Decode("weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ");
            byte[] bob_y = Base64Url.Decode("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck");
            byte[] bob_d = Base64Url.Decode("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw");

            byte[] ephemeral_x = Base64Url.Decode("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0");
            byte[] ephemeral_y = Base64Url.Decode("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps");

            byte[] algorithmId = new byte[] { 0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77 };
            byte[] partyUInfo = new byte[] { 0, 0, 0, 5, 65, 108, 105, 99, 101 };
            byte[] partyVInfo = new byte[] { 0, 0, 0, 3, 66, 111, 98 };
            byte[] suppPubInfo = new byte[] { 0, 0, 0, 128 };

            //when
            byte[] key = ConcatKDF.DeriveKeyNonCng(EccKey.New(ephemeral_x, ephemeral_y, usage: CngKeyUsages.KeyAgreement),
                EccKey.New(bob_x, bob_y, bob_d, usage: CngKeyUsages.KeyAgreement), 128, algorithmId, partyVInfo,
                partyUInfo, suppPubInfo);

            string test = Base64Url.Encode(key);

            //then
            Assert.Equal("VqqN6vgjbSBcIijNcacQGg", test);
        }
        
        [Fact]
        public void Derive128BitKeyNonCng()
        {
            // https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23#appendix-C

            //given
            byte[] bob_x = Base64Url.Decode("weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ");
            byte[] bob_y = Base64Url.Decode("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck");
            byte[] bob_d = Base64Url.Decode("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw");

            byte[] ephemeral_x = Base64Url.Decode("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0");
            byte[] ephemeral_y = Base64Url.Decode("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps");

            byte[] algorithmId = new byte[] { 0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77 };
            byte[] partyUInfo = new byte[] { 0, 0, 0, 5, 65, 108, 105, 99, 101 };
            byte[] partyVInfo = new byte[] { 0, 0, 0, 3, 66, 111, 98 };
            byte[] suppPubInfo = new byte[] { 0, 0, 0, 128 };
            
            using var publicKey = CreateEcDiffieHellman(ECCurve.NamedCurves.nistP256, ephemeral_x, ephemeral_y, null);
            using var privateKey = CreateEcDiffieHellman(ECCurve.NamedCurves.nistP256, bob_x, bob_y, bob_d);
            
            var derivedKey = ConcatKDF.DeriveKeyNonCng(publicKey, privateKey, 128, algorithmId, partyVInfo, partyUInfo, suppPubInfo);

            string test = Base64Url.Encode(derivedKey);

            //then
            Assert.Equal("VqqN6vgjbSBcIijNcacQGg", test);
        }

        [Fact]
        public void Derive256BitKeyNonCng()
        {
            const int cekSizeBits = 256;
            const string algorithmType = "ECDH-ES";

            var enc = Encoding.UTF8.GetBytes(algorithmType);
            var apu = Array.Empty<byte>();
            var apv = Array.Empty<byte>();

            var algorithmId = Arrays.Concat(Arrays.IntToBytes(enc.Length), enc);
            var partyUInfo = Arrays.Concat(Arrays.IntToBytes(apu.Length), apu);
            var partyVInfo = Arrays.Concat(Arrays.IntToBytes(apv.Length), apv);
            var suppPubInfo = Arrays.IntToBytes(cekSizeBits);
                
            using var privateKey = CreateEcDiffieHellman(ECCurve.NamedCurves.nistP256, "3BDv2y0CqT9A28qOhJoSp9K6qNSEaGagF6TLuVtCR5g=", "AkR4kvGNucKbDyHW7d5iD/C37aJML+4V+rxcyeXN0ts=", "Zw1DgcQ2LAex8SBaceej1yCB6IaSPFfBz05JccmImCo=");
            using var publicKey = CreateEcDiffieHellman(ECCurve.NamedCurves.nistP256, "YZAG4YKtXl/sQW+kTERkV3CTjU4CqUeVAFcROMivNYQ=", "u2iWhH749lKT6YMjkGC5eU26/wfM5PsZNSojgnQOD30=", null);

            var derivedKey = ConcatKDF.DeriveKeyNonCng(publicKey, privateKey, cekSizeBits, algorithmId, partyVInfo, partyUInfo, suppPubInfo);
            
            var result = Convert.ToBase64String(derivedKey);
            
            Assert.Equal("d33muATOW7cEBggxhYr+8ZeKtNgFNh8inXomWnkQDFo=", result);
        }

        private static ECDiffieHellman CreateEcDiffieHellman(ECCurve curve, string x, string y, string d)
        {
            var privateParameters = new ECParameters
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = Convert.FromBase64String(x),
                    Y = Convert.FromBase64String(y)
                }
            };

            if (!String.IsNullOrWhiteSpace(d))
            {
                privateParameters.D = Convert.FromBase64String(d);
            }

            return ECDiffieHellman.Create(privateParameters);
        }
        
        private static ECDiffieHellman CreateEcDiffieHellman(ECCurve curve, byte[] x, byte[] y, byte[] d)
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
    }
}