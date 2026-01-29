using Jose;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests.encoding
{
    public class DerTest
    {
        private readonly TestConsole Console;
        private ITestSuiteUtils testSuiteUtils;

        public DerTest(ITestOutputHelper output)
        {
            this.Console = new TestConsole(output);
            testSuiteUtils = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? (ITestSuiteUtils)new TestSuiteCngKeyUtils() : new TestSuiteEcdhUtils();
        }

        [Fact]
        public void ToP1363()
        {
            //given
            var asn1Signature = new byte[] { 48, 69, 2, 32, 107, 220, 182, 187, 167, 215, 168, 250, 93, 197, 247, 235, 17, 172, 45, 150, 127, 109, 119, 122, 28, 25, 145, 153, 224, 187, 81, 224, 27, 247, 63, 46, 2, 33, 0, 133, 195, 151, 2, 56, 255, 238, 132, 63, 107, 113, 240, 18, 31, 159, 102, 106, 181, 142, 121, 156, 33, 53, 65, 223, 116, 116, 55, 214, 216, 243, 90 };
            var p1363Signature = new byte[] { 107, 220, 182, 187, 167, 215, 168, 250, 93, 197, 247, 235, 17, 172, 45, 150, 127, 109, 119, 122, 28, 25, 145, 153, 224, 187, 81, 224, 27, 247, 63, 46, 133, 195, 151, 2, 56, 255, 238, 132, 63, 107, 113, 240, 18, 31, 159, 102, 106, 181, 142, 121, 156, 33, 53, 65, 223, 116, 116, 55, 214, 216, 243, 90 };
            
            //when
            var test = Der.ToP1363(asn1Signature);

            //then
            Assert.Equal(p1363Signature, test);
        }
        
        [Fact]
        public void ToASN1()
        {
            //given
            var p1363Signature = new byte[] { 107, 220, 182, 187, 167, 215, 168, 250, 93, 197, 247, 235, 17, 172, 45, 150, 127, 109, 119, 122, 28, 25, 145, 153, 224, 187, 81, 224, 27, 247, 63, 46, 133, 195, 151, 2, 56, 255, 238, 132, 63, 107, 113, 240, 18, 31, 159, 102, 106, 181, 142, 121, 156, 33, 53, 65, 223, 116, 116, 55, 214, 216, 243, 90 };
            var asn1Signature = new byte[] { 48, 69, 2, 32, 107, 220, 182, 187, 167, 215, 168, 250, 93, 197, 247, 235, 17, 172, 45, 150, 127, 109, 119, 122, 28, 25, 145, 153, 224, 187, 81, 224, 27, 247, 63, 46, 2, 33, 0, 133, 195, 151, 2, 56, 255, 238, 132, 63, 107, 113, 240, 18, 31, 159, 102, 106, 181, 142, 121, 156, 33, 53, 65, 223, 116, 116, 55, 214, 216, 243, 90 };
            
            //when
            var test = Der.ToASN1(p1363Signature);

            //then
            Assert.Equal(asn1Signature, test);
        }

        [Fact]
        public void ToASN1CrossTest()
        {
            //given
            var sig = Base64Url.Decode("Lkq9xKmN9c5Pvfr07t4BpE3Xty6HMl7GQ5zAU1WMjnY6hOtAQ0TK_gEX4Kunm0erHtz8jjIdLXV-pJbwkAy6RQ");

            //when
            var test = Base64Url.Encode(Der.ToASN1(sig));
            Console.Out.WriteLine("DER ASN1 = {0}", test);

            //then
            //matches jose4j encoded ASN1
            Assert.Equal("MEQCIC5KvcSpjfXOT7369O7eAaRN17cuhzJexkOcwFNVjI52AiA6hOtAQ0TK_gEX4Kunm0erHtz8jjIdLXV-pJbwkAy6RQ", test);
        }

        [Fact]
        public void ToP1361CrossTest()
        {
            //given
            // jose4j generated token            
            var asn1Sig = Base64Url.Decode("MEQCIC5KvcSpjfXOT7369O7eAaRN17cuhzJexkOcwFNVjI52AiA6hOtAQ0TK_gEX4Kunm0erHtz8jjIdLXV-pJbwkAy6RQ");
            var pubKey = new Jwk(crv: "P-256", x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU");

            //when
            var test = Base64Url.Encode(Der.ToP1363(asn1Sig));
            Console.Out.WriteLine("P1363 = {0}", test);

            var token = "eyJjdHkiOiJ0ZXh0L3BsYWluIiwiYWxnIjoiRVMyNTYifQ.eyJoZWxsbyI6ICJ3b3JsZCJ9." + test; // reconstruct full token           
            string json = Jose.JWT.Decode(token, pubKey); // and make sure verification pass

            //then
            Assert.Equal("Lkq9xKmN9c5Pvfr07t4BpE3Xty6HMl7GQ5zAU1WMjnY6hOtAQ0TK_gEX4Kunm0erHtz8jjIdLXV-pJbwkAy6RQ", test);
            Assert.Equal(@"{""hello"": ""world""}", json);
        }
    }
}