using Jose;
using System.Collections.Generic;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class JwkExampleTest
    {
        private TestConsole Console;

        public JwkExampleTest(ITestOutputHelper output)
        {
            Console = new TestConsole(output);
        }

        [Fact]
        public void EncryptedSymmetricKey()
        {
            Jwk shared = new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            var token = Jose.JWT.Encode(shared.ToJson(JWT.DefaultSettings.JsonMapper), "secret", JweAlgorithm.PBES2_HS512_A256KW, JweEncryption.A256GCM);
            Console.Out.WriteLine(token);
        }

        [Fact]
        public void SymmetricKeyInHeader()
        {
            Jwk shared = new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            var headers = new Dictionary<string, object>
            {
                {"jwk", shared.ToDictionary() }
            };

            var token = JWT.Encode(@"{""hello"": ""world""}", shared, JwsAlgorithm.HS512, headers);

            Console.Out.WriteLine(token);
        }

        [Fact]
        public void VerifyWithSymmetricKeyFromHeader()
        {
            var token = "eyJhbGciOiJIUzUxMiIsImp3ayI6eyJrdHkiOiJvY3QiLCJrIjoiR2F3Z2d1RnlHcldLYXY3QVg0VktVZyJ9fQ.eyJoZWxsbyI6ICJ3b3JsZCJ9.d8HO1eSoqgPbVZPXhsds8o_0fqf4gx0fa99UgQtIapojs52jF7xbCQykrls_sDq6J1ltYOFmJ35Hnv9XfryP1A";

            var key = Jwk.FromDictionary((IDictionary<string, object>)JWT.Headers(token)["jwk"]);

            JWT.Decode(token, key);
        }

        [Fact]
        public void DecodeAndUseSymmetricKey()
        {
            string token = "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMmMiOjgxOTIsInAycyI6Inp3eUF0TElqTXpQM01pQ0giLCJlbmMiOiJBMjU2R0NNIn0.4geBbNNUErAkSiNmUVL23tnH3Jah0B0QkvhAaEcHeUgxRGKmWvkOjg.CCNy7C1HOH-qq5Lo.Uzi9FZ_b8bHenXF7h-D63gZCASdvLA7WqnKRSXwsr7G94SnB5bHiZrUT.l6D2hJSoFPpnXPXLyOloxg";

//            var key = JWK.FromJson(
//                       Jose.JWT.Decode(token, "secret"), JWT.DefaultSettings.JsonMapper);
            var key = Jose.JWT.Decode<Jwk>(token, "secret");

            var test = JWT.Encode(@"{""hello"": ""world""}", key, JwsAlgorithm.HS512);

            Console.Out.WriteLine("key = {0}", key);
            Console.Out.WriteLine("test = {0}", key);
        }
    }
}
