using System;
using System.Security.Cryptography;
using System.Text;
using Jose;
using NUnit.Framework;
using Security.Cryptography;

namespace UnitTests
{
    [TestFixture]
    public class ConcatKDFTest
    {
        [Test]
        public void Derive128BitKey()
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

            //when
            byte[] key = ConcatKDF.DeriveKey(EccKey.New(ephemeral_x, ephemeral_y, usage: CngKeyUsages.KeyAgreement), EccKey.New(bob_x, bob_y, bob_d, usage: CngKeyUsages.KeyAgreement), 128, algorithmId, partyVInfo, partyUInfo, suppPubInfo);

            string test = Base64Url.Encode(key);

            //then
            Assert.That(test, Is.EqualTo("VqqN6vgjbSBcIijNcacQGg"));
        }
    }
}