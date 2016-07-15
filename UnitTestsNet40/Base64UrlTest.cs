using Jose;
using NUnit.Framework;

namespace UnitTests
{
    [TestFixture]
    public class Base64UrlTest
    {
        [Test]
        public void Encode()
        {
            //when
            var test = Base64Url.Encode(new byte[] {72, 101, 108, 108, 111, 32, 66, 97, 115, 101, 54, 52, 85, 114, 108, 32, 101, 110, 99, 111, 100, 105, 110, 103, 33});

            //then
            Assert.That(test, Is.EqualTo("SGVsbG8gQmFzZTY0VXJsIGVuY29kaW5nIQ"));
        }

        [Test]
        public void Decode()
        {
            //when
            var test = Base64Url.Decode("SGVsbG8gQmFzZTY0VXJsIGVuY29kaW5nIQ");

            //then
            Assert.That(test, Is.EqualTo(new byte[] { 72, 101, 108, 108, 111, 32, 66, 97, 115, 101, 54, 52, 85, 114, 108, 32, 101, 110, 99, 111, 100, 105, 110, 103, 33 }));
        }
    }
}