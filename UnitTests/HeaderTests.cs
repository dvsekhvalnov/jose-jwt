using Jose;
using Xunit;

namespace UnitTests
{
    public class HeaderTests
    {

        [Fact]
        public void JweHeaderFromAlg()
        {
            Assert.Equal("A256CBC-HS512", Headers.Jwe(JweEncryption.A256CBC_HS512));
        }

        [Fact]
        public void JweAlgFromHeader()
        {
            Assert.Equal(JweEncryption.A192CBC_HS384, Headers.Jwe("A192CBC-HS384"));
        }

        [Fact]
        public void JweAlgFromUnknownHeader()
        {
            Assert.Null(Headers.Jwe("A512CBC-HS1024"));
        }
    }
}
