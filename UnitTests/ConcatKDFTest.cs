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
        public void Derive128BitCngKey()
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
            byte[] key = ConcatKDF.DeriveKey(EccKey.New(ephemeral_x, ephemeral_y, usage: CngKeyUsages.KeyAgreement),
                EccKey.New(bob_x, bob_y, bob_d, usage: CngKeyUsages.KeyAgreement), 128, algorithmId, partyVInfo,
                partyUInfo, suppPubInfo);

            string test = Base64Url.Encode(key);

            //then
            Assert.Equal("VqqN6vgjbSBcIijNcacQGg", test);
        }
        
        [Fact]
        public void Derive128BitEcdhKey()
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
            
            var derivedKey = ConcatKDF.DeriveEcdhKey(publicKey, privateKey, 128, algorithmId, partyVInfo, partyUInfo, suppPubInfo);

            string test = Base64Url.Encode(derivedKey);

            //then
            Assert.Equal("VqqN6vgjbSBcIijNcacQGg", test);
        }

        [Fact]
        public void Derive192BitEcdhKey()
        {
            var algorithmId = new byte[] { 0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77 };
            var partyUInfo = new byte[] { 0, 0, 0, 5, 65, 108, 105, 99, 101 };
            var partyVInfo = new byte[] { 0, 0, 0, 3, 66, 111, 98 };
            var suppPubInfo = Arrays.IntToBytes(192);

            using var privateKey = CreateEcDiffieHellman(ECCurve.NamedCurves.nistP384, "Rpfcsz4AT-hyQDpLW9HogAeJlyoNlA-FXdcHA4h8DmXyz8BF1JFYO94hfy4e2q9P", "vcrEHpk1FnqrBLwqRwIJwb8Rb7ROBm6Z8JPLLZjstZzo3-OURJTdsDmVLMtTVUs3", "ice3abxagFJ0L6Fk3WHQQK33CSq6vbVuGOH-iEuc8tFe2joOIb4PUo3uz9afjPeL");
            using var publicKey = CreateEcDiffieHellman(ECCurve.NamedCurves.nistP384, "YaSJKhKhyN22PlHkZ-6EGItMZy4wbJ3SOtXec0U5BVoBsM1p3lCkKrIRX_Xh7kW9", "lsHvjg_WJPHjZaNi-Mh2TaJ2_ULKTQpodmLVXLJegoEhxaxePoWxFEznj2iDATpa", null);

            var derivedKey = ConcatKDF.DeriveEcdhKey(publicKey, privateKey, 192, algorithmId, partyVInfo, partyUInfo, suppPubInfo);

            var result = Convert.ToBase64String(derivedKey);

            Assert.Equal("NMMLkEa2KgEQ6hsTdDnSj/09lup5Yzox", result);
        }

        [Fact]
        public void Derive256BitEcdhKey()
        {
            var algorithmId = new byte[] { 0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77 };
            var partyUInfo = new byte[] { 0, 0, 0, 5, 65, 108, 105, 99, 101 };
            var partyVInfo = new byte[] { 0, 0, 0, 3, 66, 111, 98 };
            var suppPubInfo = Arrays.IntToBytes(256);

            using var privateKey = CreateEcDiffieHellman(ECCurve.NamedCurves.nistP521, "APhJyzW4IkVv2eb_bNTx5V_vXYNkJVaYV2KqKxkjUIk-cMVxinRyN6WACIuU7W15KM0DPX8cwzor5ODkUuDblMxg", "ADxHYXBqI3lQthSnjwj2bOqgwQoDlC0LOrG-rBqyvPBbGUNPQPHLQd_aDONSskKgE8LZrD36F07agqBp2NDrfC4g", "AN6BCYXPe3SwU1-pHXmgiRYVsDvLgT5vE04OrhTTOKBTKkrb0CfnIVRyR2ptoXTzppL854nkY5WYe8mdm4O1arNw");
            using var publicKey = CreateEcDiffieHellman(ECCurve.NamedCurves.nistP521, "AdAzI7PoZxswcUGbbZ0GcqfK5RB7DGxHn9lgCAjIk7sw94tLRCO8dZAf51SEaOLjvuzmpL4rmH0HDxmjO6yiNE-P", "AXYEHTg6IFSR2Y6WYESdV8-WCLgyqsFAZ7sHqY4u79OqB-LeUS7azzoEZ1g8VXwn39B3P2ziEnqhxif4UUgwMCr9", null);

            var derivedKey = ConcatKDF.DeriveEcdhKey(publicKey, privateKey, 256, algorithmId, partyVInfo, partyUInfo, suppPubInfo);

            var result = Convert.ToBase64String(derivedKey);           

            Assert.Equal("WAnUexiVf70F1vj1smMO9v5j339zpla9HEbKt/AVWgw=", result);
        }

        private static ECDiffieHellman CreateEcDiffieHellman(ECCurve curve, string x, string y, string d)
        {
            var privateParameters = new ECParameters
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = Base64Url.Decode(x),
                    Y = Base64Url.Decode(y)
                }
            };

            if (!String.IsNullOrWhiteSpace(d))
            {
                privateParameters.D = Base64Url.Decode(d);
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