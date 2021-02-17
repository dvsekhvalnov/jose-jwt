using Jose;
using Jose.keys;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests.jwe
{
    public class JWCryptoTest
    {
        private static readonly byte[] sharedKey = new byte[] { 21, 26, 196, 88, 134, 11, 137, 127, 215, 118, 142, 180, 138, 115, 246, 247, 179, 182, 140, 136, 76, 33, 206, 189, 255, 22, 243, 100, 251, 74, 254, 161 };

        private TestConsole Console;

        public JWCryptoTest(ITestOutputHelper output)
        {
            this.Console = new TestConsole(output);
        }

        [Fact]
        public void DecodeKeySingleRecipientProtectedHeader()
        {
            var token = @"{""ciphertext"":""tzh1xXdNDke99sLmZEnmYw"",""encrypted_key"":""DNszn45AFTiUAWsPeLi-AZd4oSkUKLK95FrRMpDv9qEe9TIA6QOPezOh7NrOzTXa8AdrbnDRQJwO7S_0i4p5xQrEukjkzelD"",""header"":{""alg"":""A256KW"",""enc"":""A256CBC-HS512""},""iv"":""480QxkaQPCiaEmxJFPxgsg"",""tag"":""dHeG5UCb4nCSbysUKva_4I_Z4D2WfYUaeasxOsJXTYg""}";

            var payload = Jose.Jwe.JWE.Decrypt(token, sharedKey);

            Assert.Equal("Hello World", System.Text.Encoding.UTF8.GetString(payload.Plaintext));

            Assert.Equal(payload.JoseHeaders.Count, 2);
            Assert.Equal(payload.JoseHeaders["enc"], "A256CBC-HS512");
            Assert.Equal(payload.JoseHeaders["alg"], "A256KW");
        } 

        [Fact]
        public void DecodeMultipleRecipientsNoProtectedHeader()
        {           
            var token = @"{
	            ""ciphertext"": ""zKxWBKEUDF4cucE"",
	            ""iv"": ""vEF_GqDbgyblOZ-i"",
	            ""recipients"": [
		            {
			            ""encrypted_key"": ""UDhZR9USzDByzrhxFtKYxzi5lUVvsze7kpjdfxMhDxyG5cKf2ldmqQ"",
			            ""header"": {
				            ""alg"": ""A256KW"",
				            ""enc"": ""A256GCM""
			            }
		            },
		            {
			            ""encrypted_key"": ""euWT-ji1Iud_oCCvnTrHTSZ37kh_6cUNaGXLqCQWClCNRksCkcFUasoDWwQBby_kpOihe0yoc-AL3Jm_jrdO1YyovumKLBgygwDyBttdl5sBW9EvabyJWu9Q6tAv_fJYhx-icOJyTtG133zHeymx_vTyBKtJ9-S3zCfMPBFl2Yy0mn34f9EIxfENBuYmpKyEcTvXO9LXpjQuTyBpxxTd6jjoMjESHzH0xL4WWugQCGpgY2zilW_bOBZRmZ8wxEhB0oKSCjY13b9ZeGcWgK0rQAt-ekw9dKAp2rz7jOLceFwyvbhpKrtBgbWHiaMBKNoRb6djRX0Z_Tn79Fc-VUvVBA"",
			            ""header"": {
				            ""alg"": ""RSA-OAEP-256"",
				            ""enc"": ""A256GCM"",
				            ""typ"": ""JWE""
			            }
		            }
	            ],
	            ""tag"": ""9UFM1EdyzU3ExyrtLaWaQg""
            }";

            var firstRecipient = Jose.Jwe.JWE.Decrypt(token, sharedKey);

            Assert.Equal("Hello World", System.Text.Encoding.UTF8.GetString(firstRecipient.Plaintext));

            Assert.Equal(firstRecipient.JoseHeaders.Count, 2);
            Assert.Equal(firstRecipient.JoseHeaders["enc"], "A256GCM");
            Assert.Equal(firstRecipient.JoseHeaders["alg"], "A256KW");

            var secondRecipient = Jose.Jwe.JWE.Decrypt(token, PrivKey());

            Assert.Equal("Hello World", System.Text.Encoding.UTF8.GetString(secondRecipient.Plaintext));

            Assert.Equal(secondRecipient.JoseHeaders.Count, 3);
            Assert.Equal(secondRecipient.JoseHeaders["enc"], "A256GCM");
            Assert.Equal(secondRecipient.JoseHeaders["typ"], "JWE");
            Assert.Equal(secondRecipient.JoseHeaders["alg"], "RSA-OAEP-256");
        }

        [Fact]
        public void DecodeMultipleRecipientsWithProtectedHeader()
        {
            var token = @"{
	            ""ciphertext"": ""hPHYxxZWLWxI5g224mPnAA"",
	            ""iv"": ""r_DCANXTkVo1TEwkd-Cx1w"",
	            ""protected"": ""eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldFIn0"",
	            ""recipients"": [
		            {
			            ""encrypted_key"": ""KqEaCvRWCxZW9kG3eaf4ekL1nf5YWjv_m96QVjOaSV0H5O1lORQkDCkuNrWYwHLMGAEgXSaGGRXFIdFuG68zgVQJ5u1I7Ona"",
			            ""header"": {
				            ""alg"": ""A256KW""
			            }
		            },
		            {
			            ""encrypted_key"": ""EYPZerMlLRu0LU1yfNiNNnl92Stz36hzM-NMNiBHmBLyysg6JTOi8PB2QOh4FUKO-YWpq80iacMiUniGmEnRrK8x4n4_acYADtj_36aKf5guJ3XOWjpm8BfTRtLJ-D7OlrDlLnn23pQHYlYHAXZMEky1JRbUbpt-1Jf1raHUUZIxSS2s2aZxkxpQR8lgfId3aPwzGdIqPWgWvKsNtR510E8RSKJVatNL5uGwDDo1F5gpxIThdUcNAAoINaBlpbBUWQvefRAQYzOT25jcmCuNQmKMPJrhsZZpyC4QVvjJ5nXqi027xHKelOIaUkpliPFmnq2rFp0RDFe_Kcq7_hk86A"",
			            ""header"": {
				            ""alg"": ""RSA-OAEP-256"",
				            ""kid"": ""Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc""
			            }
		            }
	            ],
	            ""tag"": ""q_8tx6Ud3q-X1K6NKaYF_qfUriicAm8M4eRX7H75N04""
            }";

            var firstRecipient = Jose.Jwe.JWE.Decrypt(token, sharedKey);

            Assert.Equal("Hello World", System.Text.Encoding.UTF8.GetString(firstRecipient.Plaintext));

            Assert.Equal(firstRecipient.JoseHeaders.Count, 3);
            Assert.Equal(firstRecipient.JoseHeaders["enc"], "A256CBC-HS512");
            Assert.Equal(firstRecipient.JoseHeaders["typ"], "JWE");
            Assert.Equal(firstRecipient.JoseHeaders["alg"], "A256KW");
            
            var secondRecipient = Jose.Jwe.JWE.Decrypt(token, PrivKey());

            Assert.Equal("Hello World", System.Text.Encoding.UTF8.GetString(secondRecipient.Plaintext));

            Assert.Equal(secondRecipient.JoseHeaders.Count, 4);
            Assert.Equal(secondRecipient.JoseHeaders["enc"], "A256CBC-HS512");
            Assert.Equal(secondRecipient.JoseHeaders["typ"], "JWE");
            Assert.Equal(secondRecipient.JoseHeaders["alg"], "RSA-OAEP-256");
            Assert.Equal(secondRecipient.JoseHeaders["kid"], "Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc");            
        }

        [Fact]
        public void DecodeMultipleRecipientsWithUnprotectedHeader()
        {
            var token = @"{
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
            }";

            var firstRecipient = Jose.Jwe.JWE.Decrypt(token, "secret");

            Assert.Equal("Hello World", System.Text.Encoding.UTF8.GetString(firstRecipient.Plaintext));

            Assert.Equal(firstRecipient.JoseHeaders.Count, 5);
            Assert.Equal(firstRecipient.JoseHeaders["enc"], "A256CBC-HS512");
            Assert.Equal(firstRecipient.JoseHeaders["typ"], "JWE");
            Assert.Equal(firstRecipient.JoseHeaders["alg"], "PBES2-HS256+A128KW");
            Assert.Equal(firstRecipient.JoseHeaders["p2c"], 8192);
            Assert.Equal(firstRecipient.JoseHeaders["p2s"], "C5Hn0y-ho1mwygXPVfDynQ");

            var secondRecipient = Jose.Jwe.JWE.Decrypt(token, Ecc256Private());

            Assert.Equal("Hello World", System.Text.Encoding.UTF8.GetString(secondRecipient.Plaintext));

            Assert.Equal(secondRecipient.JoseHeaders.Count, 4);
            Assert.Equal(secondRecipient.JoseHeaders["enc"], "A256CBC-HS512");
            Assert.Equal(secondRecipient.JoseHeaders["typ"], "JWE");
            Assert.Equal(secondRecipient.JoseHeaders["alg"], "ECDH-ES+A128KW");
            Assert.True(secondRecipient.JoseHeaders.ContainsKey("epk"));

            var epk = (IDictionary<string, object>)secondRecipient.JoseHeaders["epk"];
            Assert.Equal(epk.Count, 4);
            Assert.Equal(epk["crv"], "P-256");
            Assert.Equal(epk["kty"], "EC");
            Assert.Equal(epk["x"], "LqM-HYhs3GcIPKRdiR2R7CuPx-aPVwBohgzP9l2WdfA");
            Assert.Equal(epk["y"], "0hP45SduS8HPQaZ8RAyikZTuvYCjKaknhcCSVK_tIIY");
        }

        [Fact]
        public void DecodeDuplicateKeys_ProtectedHeader_ReceipientHeader()
        {
            var token = @"{
	            ""ciphertext"": ""hPHYxxZWLWxI5g224mPnAA"",
	            ""iv"": ""r_DCANXTkVo1TEwkd-Cx1w"",
	            ""protected"": ""eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldFIn0"",
	            ""recipients"": [
		            {
			            ""encrypted_key"": ""KqEaCvRWCxZW9kG3eaf4ekL1nf5YWjv_m96QVjOaSV0H5O1lORQkDCkuNrWYwHLMGAEgXSaGGRXFIdFuG68zgVQJ5u1I7Ona"",
			            ""header"": {
				            ""alg"": ""A256KW"",
                            ""typ"": ""JWE""
                        }
		            },
		            {
			            ""encrypted_key"": ""EYPZerMlLRu0LU1yfNiNNnl92Stz36hzM-NMNiBHmBLyysg6JTOi8PB2QOh4FUKO-YWpq80iacMiUniGmEnRrK8x4n4_acYADtj_36aKf5guJ3XOWjpm8BfTRtLJ-D7OlrDlLnn23pQHYlYHAXZMEky1JRbUbpt-1Jf1raHUUZIxSS2s2aZxkxpQR8lgfId3aPwzGdIqPWgWvKsNtR510E8RSKJVatNL5uGwDDo1F5gpxIThdUcNAAoINaBlpbBUWQvefRAQYzOT25jcmCuNQmKMPJrhsZZpyC4QVvjJ5nXqi027xHKelOIaUkpliPFmnq2rFp0RDFe_Kcq7_hk86A"",
			            ""header"": {
				            ""alg"": ""RSA-OAEP-256"",
				            ""kid"": ""Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc""
			            }
		            }
	            ],
	            ""tag"": ""q_8tx6Ud3q-X1K6NKaYF_qfUriicAm8M4eRX7H75N04""
            }";            

            //then
            Assert.Throws<JoseException>(() => Jose.Jwe.JWE.Decrypt(token, sharedKey));
        }

        [Fact]
        public void DecodeDuplicateKeys_ProtectedHeader_UnprotectedHeader()
        {
            var token = @"{
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
		            ""enc"": ""A256CBC-HS512"",
                    ""typ"": ""JWE""

	            }
            }";
            //then
            Assert.Throws<JoseException>(() => Jose.Jwe.JWE.Decrypt(token, sharedKey));
        }

		[Fact]
		public void DecodeDuplicateKeys_UnprotectedHeader_RecipientHeader()
		{
			var token = @"{
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
		            ""enc"": ""A256CBC-HS512"",
                    ""alg"": ""ECDH-ES+A128KW""

	            }
            }";
			//then
			Assert.Throws<JoseException>(() => Jose.Jwe.JWE.Decrypt(token, Ecc256Private()));
		}

		private static RSA PrivKey()
        {
            return X509().GetRSAPrivateKey();
        }

        private static RSA PubKey()
        {
            return X509().GetRSAPublicKey();
        }

        private static X509Certificate2 X509()
        {
            return new X509Certificate2("jwt-2048.p12", "1", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }

        private CngKey Ecc256Private()
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EccKey.New(x, y, d, CngKeyUsages.KeyAgreement);

        }

    }
}
