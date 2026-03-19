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

        [Fact]
        public void JwsHeaderFromAlg()
        {
            Assert.Equal("RS256", Headers.Jws(JwsAlgorithm.RS256));
        }

        [Fact]
        public void JwsAlgFromHeader()
        {
            Assert.Equal(JwsAlgorithm.ES512, Headers.Jws("ES512"));
        }

        [Fact]
        public void JwsAlgFromUnknownHeader()
        {
            Assert.Null(Headers.Jws("ES1024"));
        }

        [Fact]
        public void JwaHeaderFromAlg()
        {
            Assert.Equal("PBES2-HS256+A128KW", Headers.Jwa(JweAlgorithm.PBES2_HS256_A128KW));
        }

        [Fact]
        public void JwaAlgFromHeader()
        {
            Assert.Equal(JweAlgorithm.RSA_OAEP_512, Headers.Jwa("RSA-OAEP-512"));
        }

        [Fact]
        public void JwaAlgFromUnknownHeader()
        {
            Assert.Null(Headers.Jwa("ECDHES"));
        }

        [Fact]
        public void CompressionHeaderFromAlg()
        {
            Assert.Equal("DEF", Headers.Zip(JweCompression.DEF));
        }

        [Fact]
        public void CompressionAlgFromHeader()
        {
            Assert.Equal(JweCompression.DEF, Headers.Zip("DEF"));
        }

        [Fact]
        public void CompressionAlgFromUnknownHeader()
        {
            Assert.Null(Headers.Zip("GZ"));
        }
    }
}
