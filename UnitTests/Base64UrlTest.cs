using Jose;
using Xunit;

namespace UnitTests
{
    public class Base64UrlTest
    {
        [Fact]
        public void Encode()
        {
            //when
            var test = Base64Url.Encode(new byte[] { 72, 101, 108, 108, 111, 32, 66, 97, 115, 101, 54, 52, 85, 114, 108, 32, 101, 110, 99, 111, 100, 105, 110, 103, 33 });

            //then
            Assert.Equal("SGVsbG8gQmFzZTY0VXJsIGVuY29kaW5nIQ", test);
        }

        [Fact]
        public void Decode()
        {
            //when
            var test = Base64Url.Decode("SGVsbG8gQmFzZTY0VXJsIGVuY29kaW5nIQ");

            //then
            Assert.Equal(new byte[] { 72, 101, 108, 108, 111, 32, 66, 97, 115, 101, 54, 52, 85, 114, 108, 32, 101, 110, 99, 111, 100, 105, 110, 103, 33 }, test);
        }
    }
}