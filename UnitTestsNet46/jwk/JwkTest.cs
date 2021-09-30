using Jose;
using System.Collections.Generic;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class JwkTest
    {
        private TestConsole Console;

        public JwkTest(ITestOutputHelper output)
        {
            Console = new TestConsole(output);
        }

        [Fact]
        public void ToDictionary_OctKey()
        {
            //given
            var key = new JWK(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            //when
            var test = key.ToDictionary();

            //then
            Assert.Equal(2, test.Count);
            Assert.Equal("oct", test["kty"]);
            Assert.Equal("GawgguFyGrWKav7AX4VKUg", test["k"]);
        }

        [Fact]
        public void FromDictionary_OctKey()
        {
            //given
            var data = new Dictionary<string, object>
            { 
                { "kty", "oct" }, 
                { "k", "GawgguFyGrWKav7AX4VKUg" }, 
                { "use", "sig" }, 
            };

            //when
            var test = JWK.FromDictionary(data);

            //then
            Assert.Equal(test.Kty, JWK.Oct);
            Assert.Equal(test.K, "GawgguFyGrWKav7AX4VKUg");
            Assert.Equal(test.OctKey(), new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });
        }

        [Fact]
        public void ToJson_OctKey()
        {
            //given
            var key = new JWK(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper);

            //then 
            Console.Out.WriteLine(test);

            Assert.Equal(test, @"{""kty"":""oct"",""k"":""GawgguFyGrWKav7AX4VKUg""}");
        }

        [Fact]
        public void FromJson_OctKey()
        {
            //given
            var json = @"{
                ""kty"":""oct"",
                ""use"":""sig"",
                ""k"":""GawgguFyGrWKav7AX4VKUg""
            }";

            //when
            var test = JWK.FromJson(json, JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal(test.Kty, JWK.Oct);
            Assert.Equal(test.K, "GawgguFyGrWKav7AX4VKUg");
            Assert.Equal(test.OctKey(), new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });
        }
    }
}
