using Jose;
using System.Collections.Generic;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class JweTokenTest
    {
        private readonly TestConsole Console;

        public JweTokenTest(ITestOutputHelper output)
        {
            this.Console = new TestConsole(output);
        }

        [Fact]
        public void ParseJsonEncodingSingleRecipient()
        {
            var test = JweToken.FromString(@"{
                ""ciphertext"": ""z95vPJ_gXxejpFsno9EBCQ"",
                ""iv"": ""jGdsbNjl-_uHT4V86MdFBA"",
                ""protected"": ""eyJ0eXAiOiJKV0UifQ"",
                ""encrypted_key"": ""Kpr6FHWViJNnGCuDEEl27dsCiyWHRjiYuB2dOque06oqJZGVYgu9yif0L6OKd9gWvltrGJdo_byafGF5lwIvcl6ZGCNfRF3s"",
                ""header"": {
                    ""alg"": ""PBES2-HS256+A128KW""
                },
                ""tag"": ""cbKJYp4ZRWWPWVHDyL2vuUjAZ3oAHXT1I75t1j9rCKI"",
                ""unprotected"": {
                    ""enc"": ""A256CBC-HS512""
                }
            }", JWT.DefaultSettings.JsonMapper);

            Assert.Equal(SerializationMode.Json, test.Encoding);
            Assert.Equal(new byte[] { 123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 69, 34, 125 }, test.ProtectedHeaderBytes);
            Assert.Equal(new byte[] { 207, 222, 111, 60, 159, 224, 95, 23, 163, 164, 91, 39, 163, 209, 1, 9 }, test.Ciphertext);
            Assert.Equal(new byte[] { 140, 103, 108, 108, 216, 229, 251, 251, 135, 79, 133, 124, 232, 199, 69, 4 }, test.Iv);
            Assert.Equal(new byte[] { 113, 178, 137, 98, 158, 25, 69, 101, 143, 89, 81, 195, 200, 189, 175, 185, 72, 192, 103, 122, 0, 29, 116, 245, 35, 190, 109, 214, 63, 107, 8, 162 }, test.AuthTag);
            Assert.Null(test.Aad);
            Assert.Equal(1, test.UnprotectedHeader.Count);
            Assert.Equal("A256CBC-HS512", test.UnprotectedHeader["enc"]);

            Assert.Single(test.Recipients);

            Assert.Equal(new byte[] { 42, 154, 250, 20, 117, 149, 136, 147, 103, 24, 43, 131, 16, 73, 118, 237, 219, 2, 139, 37, 135, 70, 56, 152, 184, 29, 157, 58, 171, 158, 211, 170, 42, 37, 145, 149, 98, 11, 189, 202, 39, 244, 47, 163, 138, 119, 216, 22, 190, 91, 107, 24, 151, 104, 253, 188, 154, 124, 97, 121, 151, 2, 47, 114, 94, 153, 24, 35, 95, 68, 93, 236 }, test.Recipients[0].EncryptedCek);
            Assert.Equal(1, test.Recipients[0].Header.Count);
            Assert.Equal("PBES2-HS256+A128KW", test.Recipients[0].Header["alg"]);
        }

        [Fact]
        public void ParseJsonEncoding()
        {
            // when
            var test = JweToken.FromString(@"{
                ""ciphertext"": ""z95vPJ_gXxejpFsno9EBCQ"",
                ""iv"": ""jGdsbNjl-_uHT4V86MdFBA"",
                ""protected"": ""eyJ0eXAiOiJKV0UifQ"",
                ""recipients"": [
                    {
                        ""encrypted_key"": ""Kpr6FHWViJNnGCuDEEl27dsCiyWHRjiYuB2dOque06oqJZGVYgu9yif0L6OKd9gWvltrGJdo_byafGF5lwIvcl6ZGCNfRF3s"",
                        ""header"": {
                            ""alg"": ""PBES2-HS256+A128KW"",
                            ""p2c"": 8192,
                            ""p2s"": ""C5Hn0y-ho1mwygXPVfDynQ""
                        }
                    },
                    {
                        ""encrypted_key"": ""VuzPor1OEenPP-w0qg__uGS0w4h6Yt7K2ZHtzjqj0mnAzhNzTHumYFjaivk0dUwk1H2jxieEO9FYdC48BOMMjMcylnVGTgAV"",
                        ""header"": {
                            ""alg"": ""ECDH-ES+A128KW"",
                            ""epk"": {
                                ""crv"": ""P-256"",
                                ""kty"": ""EC"",
                                ""x"": ""LqM-HYhs3GcIPKRdiR2R7CuPx-aPVwBohgzP9l2WdfA"",
                                ""y"": ""0hP45SduS8HPQaZ8RAyikZTuvYCjKaknhcCSVK_tIIY""
                            }
                        }
                    }
                ],
                ""tag"": ""cbKJYp4ZRWWPWVHDyL2vuUjAZ3oAHXT1I75t1j9rCKI"",
                ""unprotected"": {
                    ""enc"": ""A256CBC-HS512""
                }
            }", JWT.DefaultSettings.JsonMapper);

            // then
            Assert.Equal(SerializationMode.Json, test.Encoding);
            Assert.Equal(new byte[] { 123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 69, 34, 125 }, test.ProtectedHeaderBytes);
            Assert.Equal(new byte[] { 207, 222, 111, 60, 159, 224, 95, 23, 163, 164, 91, 39, 163, 209, 1, 9 }, test.Ciphertext);
            Assert.Equal(new byte[] { 140, 103, 108, 108, 216, 229, 251, 251, 135, 79, 133, 124, 232, 199, 69, 4 }, test.Iv);
            Assert.Equal(new byte[] { 113, 178, 137, 98, 158, 25, 69, 101, 143, 89, 81, 195, 200, 189, 175, 185, 72, 192, 103, 122, 0, 29, 116, 245, 35, 190, 109, 214, 63, 107, 8, 162 }, test.AuthTag);
            Assert.Null(test.Aad);
            Assert.Equal(1, test.UnprotectedHeader.Count);
            Assert.Equal("A256CBC-HS512", test.UnprotectedHeader["enc"]);


            Assert.Equal(2, test.Recipients.Count);

            Assert.Equal(new byte[] { 42, 154, 250, 20, 117, 149, 136, 147, 103, 24, 43, 131, 16, 73, 118, 237, 219, 2, 139, 37, 135, 70, 56, 152, 184, 29, 157, 58, 171, 158, 211, 170, 42, 37, 145, 149, 98, 11, 189, 202, 39, 244, 47, 163, 138, 119, 216, 22, 190, 91, 107, 24, 151, 104, 253, 188, 154, 124, 97, 121, 151, 2, 47, 114, 94, 153, 24, 35, 95, 68, 93, 236 }, test.Recipients[0].EncryptedCek);
            Assert.Equal(3, test.Recipients[0].Header.Count);
            Assert.Equal("PBES2-HS256+A128KW", test.Recipients[0].Header["alg"]);
            Assert.Equal(8192L, test.Recipients[0].Header["p2c"]);
            Assert.Equal("C5Hn0y-ho1mwygXPVfDynQ", test.Recipients[0].Header["p2s"]);

            Assert.Equal(new byte[] { 86, 236, 207, 162, 189, 78, 17, 233, 207, 63, 236, 52, 170, 15, 255, 184, 100, 180, 195, 136, 122, 98, 222, 202, 217, 145, 237, 206, 58, 163, 210, 105, 192, 206, 19, 115, 76, 123, 166, 96, 88, 218, 138, 249, 52, 117, 76, 36, 212, 125, 163, 198, 39, 132, 59, 209, 88, 116, 46, 60, 4, 227, 12, 140, 199, 50, 150, 117, 70, 78, 0, 21 }, test.Recipients[1].EncryptedCek);
            Assert.Equal(2, test.Recipients[1].Header.Count);
            Assert.Equal("ECDH-ES+A128KW", test.Recipients[1].Header["alg"]);
            var epk = (IDictionary<string, object>)test.Recipients[1].Header["epk"];
            Assert.Equal(4, epk.Count);
            Assert.Equal("P-256", epk["crv"]);
            Assert.Equal("EC", epk["kty"]);
            Assert.Equal("LqM-HYhs3GcIPKRdiR2R7CuPx-aPVwBohgzP9l2WdfA", epk["x"]);
            Assert.Equal("0hP45SduS8HPQaZ8RAyikZTuvYCjKaknhcCSVK_tIIY", epk["y"]);
        }

        [Fact]
        public void ParseCompactEncoding()
        {
            // when
            var test = JweToken.FromString("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.FojyyzygtFOyNBjzqTRfr9HVHPrvtqbVUt9sXSuU59ZhLlzk7FrirryFnFGtj8YC9lx-IX156Ro9rBaJTCU_dfERd05DhPMffT40rdcDiLxfCLOY0E2PfsMyGQPhI6YtNBtf_sQjXWEBC59zH_VoswFAUstkvXY9eVVecoM-W9HFlIxwUXMVpEPtS96xZX5LMksDgJ9sYDTNa6EQOA0hfzw07fD_FFJShcueqJuoJjILYbad-AHbpnLTV4oTbFTYjskRxpEYQr9plFZsT4_xKiCU89slT9EFhmuaiUI_-NGdX-kNDyQZj2Vtid4LSOVv5kGxyygThuQb6wjr1AGe1g.O92pf8iqwlBIQmXA.YdGjkN7lzeKYIv743XlPRYTd3x4VA0xwa5WVoGf1hiHlhQuXGEg4Jv3elk4JoFJzgVuMMQMex8fpFFL3t5I4H9bH18pbrEo7wLXvGOsP971cuOOaXPxhX6qClkwx5qkWhcTbO_2AuJxzIaU9qBwtwWaxJm9axofAPYgYbdaMZkU4F5sFdaFY8IOe94wUA1Ocn_gxC_DYp9IEAyZut0j5RImmthPgiRO_0pK9OvusE_Xg3iGfdxu70x0KpoItuNwlEf0LUA.uP5jOGMxtDUiT6E3ubucBw");

            // then
            Assert.Equal(new byte[] { 123, 34, 97, 108, 103, 34, 58, 34, 82, 83, 65, 49, 95, 53, 34, 44, 34, 101, 110, 99, 34, 58, 34, 65, 49, 50, 56, 71, 67, 77, 34, 125 }, test.ProtectedHeaderBytes);
            Assert.Equal(new byte[] { 59, 221, 169, 127, 200, 170, 194, 80, 72, 66, 101, 192 }, test.Iv);
            Assert.Equal(new byte[] { 97, 209, 163, 144, 222, 229, 205, 226, 152, 34, 254, 248, 221, 121, 79, 69, 132, 221, 223, 30, 21, 3, 76, 112, 107, 149, 149, 160, 103, 245, 134, 33, 229, 133, 11, 151, 24, 72, 56, 38, 253, 222, 150, 78, 9, 160, 82, 115, 129, 91, 140, 49, 3, 30, 199, 199, 233, 20, 82, 247, 183, 146, 56, 31, 214, 199, 215, 202, 91, 172, 74, 59, 192, 181, 239, 24, 235, 15, 247, 189, 92, 184, 227, 154, 92, 252, 97, 95, 170, 130, 150, 76, 49, 230, 169, 22, 133, 196, 219, 59, 253, 128, 184, 156, 115, 33, 165, 61, 168, 28, 45, 193, 102, 177, 38, 111, 90, 198, 135, 192, 61, 136, 24, 109, 214, 140, 102, 69, 56, 23, 155, 5, 117, 161, 88, 240, 131, 158, 247, 140, 20, 3, 83, 156, 159, 248, 49, 11, 240, 216, 167, 210, 4, 3, 38, 110, 183, 72, 249, 68, 137, 166, 182, 19, 224, 137, 19, 191, 210, 146, 189, 58, 251, 172, 19, 245, 224, 222, 33, 159, 119, 27, 187, 211, 29, 10, 166, 130, 45, 184, 220, 37, 17, 253, 11, 80 }, test.Ciphertext);
            Assert.Equal(new byte[] { 184, 254, 99, 56, 99, 49, 180, 53, 34, 79, 161, 55, 185, 187, 156, 7 }, test.AuthTag);
            Assert.Null(test.UnprotectedHeader);
            Assert.Null(test.Aad);
            Assert.Equal(SerializationMode.Compact, test.Encoding);
            Assert.Single(test.Recipients);
            Assert.Equal(new byte[] { 22, 136, 242, 203, 60, 160, 180, 83, 178, 52, 24, 243, 169, 52, 95, 175, 209, 213, 28, 250, 239, 182, 166, 213, 82, 223, 108, 93, 43, 148, 231, 214, 97, 46, 92, 228, 236, 90, 226, 174, 188, 133, 156, 81, 173, 143, 198, 2, 246, 92, 126, 33, 125, 121, 233, 26, 61, 172, 22, 137, 76, 37, 63, 117, 241, 17, 119, 78, 67, 132, 243, 31, 125, 62, 52, 173, 215, 3, 136, 188, 95, 8, 179, 152, 208, 77, 143, 126, 195, 50, 25, 3, 225, 35, 166, 45, 52, 27, 95, 254, 196, 35, 93, 97, 1, 11, 159, 115, 31, 245, 104, 179, 1, 64, 82, 203, 100, 189, 118, 61, 121, 85, 94, 114, 131, 62, 91, 209, 197, 148, 140, 112, 81, 115, 21, 164, 67, 237, 75, 222, 177, 101, 126, 75, 50, 75, 3, 128, 159, 108, 96, 52, 205, 107, 161, 16, 56, 13, 33, 127, 60, 52, 237, 240, 255, 20, 82, 82, 133, 203, 158, 168, 155, 168, 38, 50, 11, 97, 182, 157, 248, 1, 219, 166, 114, 211, 87, 138, 19, 108, 84, 216, 142, 201, 17, 198, 145, 24, 66, 191, 105, 148, 86, 108, 79, 143, 241, 42, 32, 148, 243, 219, 37, 79, 209, 5, 134, 107, 154, 137, 66, 63, 248, 209, 157, 95, 233, 13, 15, 36, 25, 143, 101, 109, 137, 222, 11, 72, 229, 111, 230, 65, 177, 203, 40, 19, 134, 228, 27, 235, 8, 235, 212, 1, 158, 214 }, test.Recipients[0].EncryptedCek);
            Assert.Empty(test.Recipients[0].Header);
        }

        [Fact]
        public void SerializeJsonEncodingSingleRecipient()
        {
            var recipients = new List<JweRecipient>
            {
                new JweRecipient(
                    new byte[] { 42, 154, 250, 20, 117, 149, 136, 147, 103, 24, 43, 131, 16, 73, 118, 237, 219, 2, 139, 37, 135, 70, 56, 152, 184, 29, 157, 58, 171, 158, 211, 170, 42, 37, 145, 149, 98, 11, 189, 202, 39, 244, 47, 163, 138, 119, 216, 22, 190, 91, 107, 24, 151, 104, 253, 188, 154, 124, 97, 121, 151, 2, 47, 114, 94, 153, 24, 35, 95, 68, 93, 236 },
                    new Dictionary<string, object>
                    {
                        { "alg", "PBES2-HS256+A128KW" }
                    }
                )
            };

            // given
            JweToken token = new JweToken(
                new byte[] { 123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 69, 34, 125 },
                null,
                recipients,
                null,
                new byte[] { 140, 103, 108, 108, 216, 229, 251, 251, 135, 79, 133, 124, 232, 199, 69, 4 },
                new byte[] { 207, 222, 111, 60, 159, 224, 95, 23, 163, 164, 91, 39, 163, 209, 1, 9 },
                new byte[] { 113, 178, 137, 98, 158, 25, 69, 101, 143, 89, 81, 195, 200, 189, 175, 185, 72, 192, 103, 122, 0, 29, 116, 245, 35, 190, 109, 214, 63, 107, 8, 162 },
                SerializationMode.Json
            );

            // when
            string test = token.AsString(JWT.DefaultSettings.JsonMapper);

            // then
            Assert.Equal(@"{""ciphertext"":""z95vPJ_gXxejpFsno9EBCQ"",""protected"":""eyJ0eXAiOiJKV0UifQ"",""iv"":""jGdsbNjl-_uHT4V86MdFBA"",""tag"":""cbKJYp4ZRWWPWVHDyL2vuUjAZ3oAHXT1I75t1j9rCKI"",""header"":{""alg"":""PBES2-HS256+A128KW""},""encrypted_key"":""Kpr6FHWViJNnGCuDEEl27dsCiyWHRjiYuB2dOque06oqJZGVYgu9yif0L6OKd9gWvltrGJdo_byafGF5lwIvcl6ZGCNfRF3s""}", test);
        }

        [Fact]
        public void SerializeJsonEncodingMultipleRecipient()
        {
            var recipients = new List<JweRecipient>
            {
                new JweRecipient(
                    new byte[] { 42, 154, 250, 20, 117, 149, 136, 147, 103, 24, 43, 131, 16, 73, 118, 237, 219, 2, 139, 37, 135, 70, 56, 152, 184, 29, 157, 58, 171, 158, 211, 170, 42, 37, 145, 149, 98, 11, 189, 202, 39, 244, 47, 163, 138, 119, 216, 22, 190, 91, 107, 24, 151, 104, 253, 188, 154, 124, 97, 121, 151, 2, 47, 114, 94, 153, 24, 35, 95, 68, 93, 236 },
                    new Dictionary<string, object>
                    {
                        { "alg", "PBES2-HS256+A128KW" }
                    }
                ),

                new JweRecipient(
                    new byte[] { 86, 236, 207, 162, 189, 78, 17, 233, 207, 63, 236, 52, 170, 15, 255, 184, 100, 180, 195, 136, 122, 98, 222, 202, 217, 145, 237, 206, 58, 163, 210, 105, 192, 206, 19, 115, 76, 123, 166, 96, 88, 218, 138, 249, 52, 117, 76, 36, 212, 125, 163, 198, 39, 132, 59, 209, 88, 116, 46, 60, 4, 227, 12, 140, 199, 50, 150, 117, 70, 78, 0, 21 },
                    new Dictionary<string, object>
                    {
                        { "alg", "ECDH-ES+A128KW" },
                        { "epk", new Dictionary<string, object>
                            {
                                { "crv", "P-256" },
                                { "kty", "EC" }
                            }
                        }
                    }
                )
            };

            // given
            JweToken token = new JweToken(
                new byte[] { 123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 69, 34, 125 },
                null,
                recipients,
                null,
                new byte[] { 140, 103, 108, 108, 216, 229, 251, 251, 135, 79, 133, 124, 232, 199, 69, 4 },
                new byte[] { 207, 222, 111, 60, 159, 224, 95, 23, 163, 164, 91, 39, 163, 209, 1, 9 },
                new byte[] { 113, 178, 137, 98, 158, 25, 69, 101, 143, 89, 81, 195, 200, 189, 175, 185, 72, 192, 103, 122, 0, 29, 116, 245, 35, 190, 109, 214, 63, 107, 8, 162 },
                SerializationMode.Json
            );

            // when
            string test = token.AsString(JWT.DefaultSettings.JsonMapper);

            // then
            Assert.Equal(@"{""ciphertext"":""z95vPJ_gXxejpFsno9EBCQ"",""protected"":""eyJ0eXAiOiJKV0UifQ"",""iv"":""jGdsbNjl-_uHT4V86MdFBA"",""tag"":""cbKJYp4ZRWWPWVHDyL2vuUjAZ3oAHXT1I75t1j9rCKI"",""recipients"":[{""header"":{""alg"":""PBES2-HS256+A128KW""},""encrypted_key"":""Kpr6FHWViJNnGCuDEEl27dsCiyWHRjiYuB2dOque06oqJZGVYgu9yif0L6OKd9gWvltrGJdo_byafGF5lwIvcl6ZGCNfRF3s""},{""header"":{""alg"":""ECDH-ES+A128KW"",""epk"":{""crv"":""P-256"",""kty"":""EC""}},""encrypted_key"":""VuzPor1OEenPP-w0qg__uGS0w4h6Yt7K2ZHtzjqj0mnAzhNzTHumYFjaivk0dUwk1H2jxieEO9FYdC48BOMMjMcylnVGTgAV""}]}", test);
        }

        [Fact]
        public void SerializeJsonEncodingAad()
        {
            // given
            var recipients = new List<JweRecipient>
            {
                new JweRecipient(
                    new byte[] { 42, 154, 250, 20, 117, 149, 136, 147, 103, 24, 43, 131, 16, 73, 118, 237, 219, 2, 139, 37, 135, 70, 56, 152, 184, 29, 157, 58, 171, 158, 211, 170, 42, 37, 145, 149, 98, 11, 189, 202, 39, 244, 47, 163, 138, 119, 216, 22, 190, 91, 107, 24, 151, 104, 253, 188, 154, 124, 97, 121, 151, 2, 47, 114, 94, 153, 24, 35, 95, 68, 93, 236 },
                    new Dictionary<string, object>
                    {
                        { "alg", "PBES2-HS256+A128KW" }
                    }
                )
            };

            JweToken token = new JweToken(
                new byte[] { 123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 69, 34, 125 },
                null,
                recipients,
                new byte[] { 123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 69, 34, 125 },
                new byte[] { 140, 103, 108, 108, 216, 229, 251, 251, 135, 79, 133, 124, 232, 199, 69, 4 },
                new byte[] { 207, 222, 111, 60, 159, 224, 95, 23, 163, 164, 91, 39, 163, 209, 1, 9 },
                new byte[] { 113, 178, 137, 98, 158, 25, 69, 101, 143, 89, 81, 195, 200, 189, 175, 185, 72, 192, 103, 122, 0, 29, 116, 245, 35, 190, 109, 214, 63, 107, 8, 162 },
                SerializationMode.Json
            );

            // when
            string test = token.AsString(JWT.DefaultSettings.JsonMapper);

            // then
            Assert.Equal(@"{""ciphertext"":""z95vPJ_gXxejpFsno9EBCQ"",""protected"":""eyJ0eXAiOiJKV0UifQ"",""iv"":""jGdsbNjl-_uHT4V86MdFBA"",""tag"":""cbKJYp4ZRWWPWVHDyL2vuUjAZ3oAHXT1I75t1j9rCKI"",""aad"":""eyJ0eXAiOiJKV0UifQ"",""header"":{""alg"":""PBES2-HS256+A128KW""},""encrypted_key"":""Kpr6FHWViJNnGCuDEEl27dsCiyWHRjiYuB2dOque06oqJZGVYgu9yif0L6OKd9gWvltrGJdo_byafGF5lwIvcl6ZGCNfRF3s""}", test);
        }

        [Fact]
        public void SerializeJsonEncodingUnprotectedHeader()
        {
            // given
            var recipients = new List<JweRecipient>
            {
                new JweRecipient(
                    new byte[] { 42, 154, 250, 20, 117, 149, 136, 147, 103, 24, 43, 131, 16, 73, 118, 237, 219, 2, 139, 37, 135, 70, 56, 152, 184, 29, 157, 58, 171, 158, 211, 170, 42, 37, 145, 149, 98, 11, 189, 202, 39, 244, 47, 163, 138, 119, 216, 22, 190, 91, 107, 24, 151, 104, 253, 188, 154, 124, 97, 121, 151, 2, 47, 114, 94, 153, 24, 35, 95, 68, 93, 236 },
                    new Dictionary<string, object>
                    {
                        { "alg", "PBES2-HS256+A128KW" }
                    }
                )
            };

            var unprotected = new Dictionary<string, object>
            {
                { "jku", "https://server.example.com/keys.jwks" }
            };

            JweToken token = new JweToken(
                new byte[] { 123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 69, 34, 125 },
                unprotected,
                recipients,
                null,
                new byte[] { 140, 103, 108, 108, 216, 229, 251, 251, 135, 79, 133, 124, 232, 199, 69, 4 },
                new byte[] { 207, 222, 111, 60, 159, 224, 95, 23, 163, 164, 91, 39, 163, 209, 1, 9 },
                new byte[] { 113, 178, 137, 98, 158, 25, 69, 101, 143, 89, 81, 195, 200, 189, 175, 185, 72, 192, 103, 122, 0, 29, 116, 245, 35, 190, 109, 214, 63, 107, 8, 162 },
                SerializationMode.Json
            );

            // when
            string test = token.AsString(JWT.DefaultSettings.JsonMapper);

            // then
            Assert.Equal(@"{""ciphertext"":""z95vPJ_gXxejpFsno9EBCQ"",""protected"":""eyJ0eXAiOiJKV0UifQ"",""iv"":""jGdsbNjl-_uHT4V86MdFBA"",""tag"":""cbKJYp4ZRWWPWVHDyL2vuUjAZ3oAHXT1I75t1j9rCKI"",""unprotected"":{""jku"":""https://server.example.com/keys.jwks""},""header"":{""alg"":""PBES2-HS256+A128KW""},""encrypted_key"":""Kpr6FHWViJNnGCuDEEl27dsCiyWHRjiYuB2dOque06oqJZGVYgu9yif0L6OKd9gWvltrGJdo_byafGF5lwIvcl6ZGCNfRF3s""}", test);
        }

        [Fact]
        public void SerializeCompact()
        {
            // given
            var recipients = new List<JweRecipient>
            {
                new JweRecipient(
                    new byte[] { 22, 136, 242, 203, 60, 160, 180, 83, 178, 52, 24, 243, 169, 52, 95, 175, 209, 213, 28, 250, 239, 182, 166, 213, 82, 223, 108, 93, 43, 148, 231, 214, 97, 46, 92, 228, 236, 90, 226, 174, 188, 133, 156, 81, 173, 143, 198, 2, 246, 92, 126, 33, 125, 121, 233, 26, 61, 172, 22, 137, 76, 37, 63, 117, 241, 17, 119, 78, 67, 132, 243, 31, 125, 62, 52, 173, 215, 3, 136, 188, 95, 8, 179, 152, 208, 77, 143, 126, 195, 50, 25, 3, 225, 35, 166, 45, 52, 27, 95, 254, 196, 35, 93, 97, 1, 11, 159, 115, 31, 245, 104, 179, 1, 64, 82, 203, 100, 189, 118, 61, 121, 85, 94, 114, 131, 62, 91, 209, 197, 148, 140, 112, 81, 115, 21, 164, 67, 237, 75, 222, 177, 101, 126, 75, 50, 75, 3, 128, 159, 108, 96, 52, 205, 107, 161, 16, 56, 13, 33, 127, 60, 52, 237, 240, 255, 20, 82, 82, 133, 203, 158, 168, 155, 168, 38, 50, 11, 97, 182, 157, 248, 1, 219, 166, 114, 211, 87, 138, 19, 108, 84, 216, 142, 201, 17, 198, 145, 24, 66, 191, 105, 148, 86, 108, 79, 143, 241, 42, 32, 148, 243, 219, 37, 79, 209, 5, 134, 107, 154, 137, 66, 63, 248, 209, 157, 95, 233, 13, 15, 36, 25, 143, 101, 109, 137, 222, 11, 72, 229, 111, 230, 65, 177, 203, 40, 19, 134, 228, 27, 235, 8, 235, 212, 1, 158, 214 }, null
                )
            };

            JweToken token = new JweToken(
                new byte[] { 123, 34, 97, 108, 103, 34, 58, 34, 82, 83, 65, 49, 95, 53, 34, 44, 34, 101, 110, 99, 34, 58, 34, 65, 49, 50, 56, 71, 67, 77, 34, 125 },
                null,
                recipients,
                null,
                new byte[] { 59, 221, 169, 127, 200, 170, 194, 80, 72, 66, 101, 192 },
                new byte[] { 97, 209, 163, 144, 222, 229, 205, 226, 152, 34, 254, 248, 221, 121, 79, 69, 132, 221, 223, 30, 21, 3, 76, 112, 107, 149, 149, 160, 103, 245, 134, 33, 229, 133, 11, 151, 24, 72, 56, 38, 253, 222, 150, 78, 9, 160, 82, 115, 129, 91, 140, 49, 3, 30, 199, 199, 233, 20, 82, 247, 183, 146, 56, 31, 214, 199, 215, 202, 91, 172, 74, 59, 192, 181, 239, 24, 235, 15, 247, 189, 92, 184, 227, 154, 92, 252, 97, 95, 170, 130, 150, 76, 49, 230, 169, 22, 133, 196, 219, 59, 253, 128, 184, 156, 115, 33, 165, 61, 168, 28, 45, 193, 102, 177, 38, 111, 90, 198, 135, 192, 61, 136, 24, 109, 214, 140, 102, 69, 56, 23, 155, 5, 117, 161, 88, 240, 131, 158, 247, 140, 20, 3, 83, 156, 159, 248, 49, 11, 240, 216, 167, 210, 4, 3, 38, 110, 183, 72, 249, 68, 137, 166, 182, 19, 224, 137, 19, 191, 210, 146, 189, 58, 251, 172, 19, 245, 224, 222, 33, 159, 119, 27, 187, 211, 29, 10, 166, 130, 45, 184, 220, 37, 17, 253, 11, 80 },
                new byte[] { 184, 254, 99, 56, 99, 49, 180, 53, 34, 79, 161, 55, 185, 187, 156, 7 },
                SerializationMode.Compact
            );

            // when
            var test = token.AsString();

            //then
            Assert.Equal("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.FojyyzygtFOyNBjzqTRfr9HVHPrvtqbVUt9sXSuU59ZhLlzk7FrirryFnFGtj8YC9lx-IX156Ro9rBaJTCU_dfERd05DhPMffT40rdcDiLxfCLOY0E2PfsMyGQPhI6YtNBtf_sQjXWEBC59zH_VoswFAUstkvXY9eVVecoM-W9HFlIxwUXMVpEPtS96xZX5LMksDgJ9sYDTNa6EQOA0hfzw07fD_FFJShcueqJuoJjILYbad-AHbpnLTV4oTbFTYjskRxpEYQr9plFZsT4_xKiCU89slT9EFhmuaiUI_-NGdX-kNDyQZj2Vtid4LSOVv5kGxyygThuQb6wjr1AGe1g.O92pf8iqwlBIQmXA.YdGjkN7lzeKYIv743XlPRYTd3x4VA0xwa5WVoGf1hiHlhQuXGEg4Jv3elk4JoFJzgVuMMQMex8fpFFL3t5I4H9bH18pbrEo7wLXvGOsP971cuOOaXPxhX6qClkwx5qkWhcTbO_2AuJxzIaU9qBwtwWaxJm9axofAPYgYbdaMZkU4F5sFdaFY8IOe94wUA1Ocn_gxC_DYp9IEAyZut0j5RImmthPgiRO_0pK9OvusE_Xg3iGfdxu70x0KpoItuNwlEf0LUA.uP5jOGMxtDUiT6E3ubucBw", test);
        }
    }
}
