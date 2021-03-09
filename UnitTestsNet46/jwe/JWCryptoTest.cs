using Jose;
using Jose.keys;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
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

            var payload = Jose.JWE.Decrypt(token, sharedKey);

            Assert.Equal("Hello World", payload.Plaintext);

            Assert.Equal(payload.Recipient.JoseHeader.Count, 2);
            Assert.Equal(payload.Recipient.JoseHeader["enc"], "A256CBC-HS512");
            Assert.Equal(payload.Recipient.JoseHeader["alg"], "A256KW");
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

            var firstRecipient = Jose.JWE.Decrypt(token, sharedKey);

            Assert.Equal("Hello World", firstRecipient.Plaintext);

            Assert.Equal(firstRecipient.Recipient.JoseHeader.Count, 2);
            Assert.Equal(firstRecipient.Recipient.JoseHeader["enc"], "A256GCM");
            Assert.Equal(firstRecipient.Recipient.JoseHeader["alg"], "A256KW");

            var secondRecipient = Jose.JWE.Decrypt(token, PrivKey());

            Assert.Equal("Hello World", secondRecipient.Plaintext);

            Assert.Equal(secondRecipient.Recipient.JoseHeader.Count, 3);
            Assert.Equal(secondRecipient.Recipient.JoseHeader["enc"], "A256GCM");
            Assert.Equal(secondRecipient.Recipient.JoseHeader["typ"], "JWE");
            Assert.Equal(secondRecipient.Recipient.JoseHeader["alg"], "RSA-OAEP-256");
        }

        [Fact]
        public void DecodeMultipleRecipientsWithProtectedHeader()
        {
            var token = @"{
				""ciphertext"": ""gVZ-iyqX3o8xlFzZD3e58g"",
				""iv"": ""iv7cQBIEzM5Jdvt1nakgvw"",
				""protected"": ""eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldFIn0"",
				""recipients"": [
					{
						""encrypted_key"": ""5xCobIXzGwDTSITcStYvDc8C636p4i4PjHsvfTCD2yaHjXuA-0YDxRj6tPDTn2rkhnRII3hhDC6XO0b_ir-OZ2FWKr01nC3a"",
						""header"": {
							""alg"": ""A256KW""
						}
					},
					{
						""encrypted_key"": ""Vx6HmM8aoem03w67iQOGiBI2B-thcLwVIZWLZavwDWRub3yZNTHlsM0FNGXhX9qhenJ-3eIBbsAwQnbdkBQaOugxHANp-xoYbWqq1FXcHiaQSRs9K1vCd-xgyJbNuqJHD3h1gEupIoxCJNAu6dypzrUcC_nLX8L6Y-H4ST_18bPFfSMbD3YatvS9k879NJzru_gigvaoyCrwW0LD1Fry05cPEl9hkyiKpnr63MmOVfGHYQvqO_xAKq02w5-LcYmuloPfpFOZEAoF3OB_4zKAcEEhEmRujSvIPrsaG3mJiRRchryiRSt5TIDO_gOkaySGQ8JFULt8zK_k5Sl0SdhZ-Q"",
						""header"": {
							""alg"": ""RSA-OAEP-256"",
							""kid"": ""Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc""
						}
					}
				],
				""tag"": ""UxOqwzlsIQsbR3W0nin1EAtez0MMgJbuNr2ZjCtmMIE""
			}";

            var firstRecipient = Jose.JWE.Decrypt(token, sharedKey);

            Assert.Equal("Hello World", firstRecipient.Plaintext);

            Assert.Equal(firstRecipient.Recipient.JoseHeader.Count, 3);
            Assert.Equal(firstRecipient.Recipient.JoseHeader["enc"], "A256CBC-HS512");
            Assert.Equal(firstRecipient.Recipient.JoseHeader["typ"], "JWE");
            Assert.Equal(firstRecipient.Recipient.JoseHeader["alg"], "A256KW");
            
            var secondRecipient = Jose.JWE.Decrypt(token, PrivKey());

            Assert.Equal("Hello World", secondRecipient.Plaintext);

            Assert.Equal(secondRecipient.Recipient.JoseHeader.Count, 4);
            Assert.Equal(secondRecipient.Recipient.JoseHeader["enc"], "A256CBC-HS512");
            Assert.Equal(secondRecipient.Recipient.JoseHeader["typ"], "JWE");
            Assert.Equal(secondRecipient.Recipient.JoseHeader["alg"], "RSA-OAEP-256");
            Assert.Equal(secondRecipient.Recipient.JoseHeader["kid"], "Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc");            
        }

        [Fact]
        public void DecodeMultipleRecipientsWithUnprotectedHeader()
        {
			var token = @"{
				""ciphertext"": ""wnecd9ceRDb0PqFdvNkjUw"",
				""iv"": ""d-F9AVZ7W6M5bWp45G_okw"",
				""protected"": ""eyJ0eXAiOiJKV0UifQ"",
				""recipients"": [
					{
						""encrypted_key"": ""gk0a-lu_f588KjKomSl8v4ULeNEXktECpLWkTyxpmtFXMDyO-BtARt1fuBkFJsYqAwUNxz4uh1u4i3QCpKxdl01tZRW1yyxR"",
						""header"": {
							""alg"": ""PBES2-HS256+A128KW"",
							""p2c"": 8192,
							""p2s"": ""kpL8s71MjhPnBExCF-cIMA""
						}
					},
					{
						""encrypted_key"": ""WDt1HtoyK0lazAF84EBoL7OWtkCyKBEj2hG_QEgX0hx2QDAgFh7HGiR5NnnChFTwdpXIA-8tBDzhWFLd6aEU8w8sqjC4txoc"",
						""header"": {
							""alg"": ""ECDH-ES+A128KW"",
							""epk"": {
								""crv"": ""P-256"",
								""kty"": ""EC"",
								""x"": ""WOqJxZwzivLSO-r3qRkBVDd9uA_de_AIu3G3hkIQg1M"",
								""y"": ""aFbCEl231v5IeA_Zjg8kMVJXxZWhpEHibtvHnq7Kk9k""
							}
						}
					}
				],
				""tag"": ""zJxGA445Q4LBp4WAXo0vdCfD8ZdrWVLGRPkUH8Sv_6I"",
				""unprotected"": {
					""enc"": ""A256CBC-HS512""
				}
			}";

            var firstRecipient = Jose.JWE.Decrypt(token, "secret");

            Assert.Equal("Hello World", firstRecipient.Plaintext);

            Assert.Equal(firstRecipient.Recipient.JoseHeader.Count, 5);
            Assert.Equal(firstRecipient.Recipient.JoseHeader["enc"], "A256CBC-HS512");
            Assert.Equal(firstRecipient.Recipient.JoseHeader["typ"], "JWE");
            Assert.Equal(firstRecipient.Recipient.JoseHeader["alg"], "PBES2-HS256+A128KW");
            Assert.Equal(firstRecipient.Recipient.JoseHeader["p2c"], 8192);
            Assert.Equal(firstRecipient.Recipient.JoseHeader["p2s"], "kpL8s71MjhPnBExCF-cIMA");

            var secondRecipient = Jose.JWE.Decrypt(token, Ecc256Private());

            Assert.Equal("Hello World", secondRecipient.Plaintext);

            Assert.Equal(secondRecipient.Recipient.JoseHeader.Count, 4);
            Assert.Equal(secondRecipient.Recipient.JoseHeader["enc"], "A256CBC-HS512");
            Assert.Equal(secondRecipient.Recipient.JoseHeader["typ"], "JWE");
            Assert.Equal(secondRecipient.Recipient.JoseHeader["alg"], "ECDH-ES+A128KW");
            Assert.True(secondRecipient.Recipient.JoseHeader.ContainsKey("epk"));

            var epk = (IDictionary<string, object>)secondRecipient.Recipient.JoseHeader["epk"];
            Assert.Equal(epk.Count, 4);
            Assert.Equal(epk["crv"], "P-256");
            Assert.Equal(epk["kty"], "EC");
            Assert.Equal(epk["x"], "WOqJxZwzivLSO-r3qRkBVDd9uA_de_AIu3G3hkIQg1M");
            Assert.Equal(epk["y"], "aFbCEl231v5IeA_Zjg8kMVJXxZWhpEHibtvHnq7Kk9k");
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
            Assert.Throws<JoseException>(() => Jose.JWE.Decrypt(token, sharedKey));
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
            Assert.Throws<JoseException>(() => Jose.JWE.Decrypt(token, sharedKey));
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
			Assert.Throws<JoseException>(() => Jose.JWE.Decrypt(token, Ecc256Private()));
		}

		[Fact]
		public void EncodeSingleRecipient()
        {
			var payload = "Hello World !";
			JweRecipient r = new JweRecipient(JweAlgorithm.A256KW, sharedKey);

			string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, mode: SerializationMode.Json);

			Console.Out.WriteLine("[JSON][A256KW][A256GCM]: {0}", token);

            JObject deserialized = JObject.Parse(token);

			Assert.Equal("{\"enc\":\"A256GCM\"}",
							 UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])));

			Assert.True(deserialized["header"] is JObject);
			Assert.Equal("{\"alg\":\"A256KW\"}", deserialized["header"].ToString(Newtonsoft.Json.Formatting.None));
			Assert.Equal("A256KW", deserialized["header"]["alg"]);
			Assert.Equal(54, ((string)deserialized["encrypted_key"]).Length); //CEK size
			Assert.Equal(16, ((string)deserialized["iv"]).Length); //IV size
			Assert.Equal(18, ((string)deserialized["ciphertext"]).Length); //cipher text size
			Assert.Equal(22, ((string)deserialized["tag"]).Length); //auth tag size


			var decoded = JWE.Decrypt(token, sharedKey);
			Assert.Equal(decoded.Plaintext, payload);
		}
		
		[Fact]
		public void EncodeMultipleRecipients()
        {
			var payload = "Hello World !";
			JweRecipient r1 = new JweRecipient(JweAlgorithm.PBES2_HS256_A128KW, "secret");
			JweRecipient r2 = new JweRecipient(JweAlgorithm.ECDH_ES_A128KW, Ecc256Public());
			JweRecipient r3 = new JweRecipient(JweAlgorithm.RSA_OAEP_256, PubKey());

			string token = JWE.Encrypt(payload, new[] { r1, r2, r3 }, JweEncryption.A256GCM, mode: SerializationMode.Json);

			Console.Out.WriteLine("[JSON][PBES2_HS256_A128KW, ECDH-ES+A128KW, RSA_OAEP_256][A256GCM]: {0}", token);

            JObject deserialized = JObject.Parse(token);

            Assert.Equal("{\"enc\":\"A256GCM\"}",
                             UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])));

            
            Assert.Equal(16, ((string)deserialized["iv"]).Length); //IV size
            Assert.Equal(18, ((string)deserialized["ciphertext"]).Length); //cipher text size
            Assert.Equal(22, ((string)deserialized["tag"]).Length); //auth tag size

			Assert.True(deserialized["recipients"] is JArray);
			Assert.Equal(3, ((JArray)deserialized["recipients"]).Count);
			var rec0 = ((JArray)deserialized["recipients"])[0];
			var rec1 = ((JArray)deserialized["recipients"])[1];
			var rec2 = ((JArray)deserialized["recipients"])[2];

			Assert.True(rec0["header"] is JObject);			
			Assert.Equal("PBES2-HS256+A128KW", rec0["header"]["alg"]);
			Assert.Equal(8192, rec0["header"]["p2c"]);
			Assert.Equal(16, ((string)rec0["header"]["p2s"]).Length);
			Assert.Equal(54, ((string)rec0["encrypted_key"]).Length);

			Assert.True(rec1["header"] is JObject);			
			Assert.True(rec1["header"]["epk"] is JObject);			
			Assert.Equal("ECDH-ES+A128KW", rec1["header"]["alg"]);
			Assert.Equal("EC", rec1["header"]["epk"]["kty"]);
			Assert.Equal("P-256", rec1["header"]["epk"]["crv"]);
			Assert.Equal(43, ((string)rec1["header"]["epk"]["x"]).Length);
			Assert.Equal(43, ((string)rec1["header"]["epk"]["y"]).Length);			
			Assert.Equal(54, ((string)rec1["encrypted_key"]).Length);

			Assert.True(rec2["header"] is JObject);
			Assert.Equal("RSA-OAEP-256", rec2["header"]["alg"]);
			Assert.Equal(342, ((string)rec2["encrypted_key"]).Length);

			Assert.Equal(JWE.Decrypt(token, "secret").Plaintext, payload);
			Assert.Equal(JWE.Decrypt(token, PrivKey()).Plaintext, payload);
			Assert.Equal(JWE.Decrypt(token, Ecc256Private()).Plaintext, payload);
		}
		
		[Fact]
		public void EncodeUnprotectedHeader()
        {
			var payload = "Hello World !";
			var unprotected = new Dictionary<string, object>
			{
				{ "jku", "https://server.example.com/keys.jwks" }
			};

			JweRecipient r = new JweRecipient(JweAlgorithm.RSA_OAEP_256, PubKey());

			string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, mode: SerializationMode.Json, unprotectedHeaders: unprotected);

			Console.Out.WriteLine("[JSON][RSA_OAEP_256][A256GCM]: {0}", token);

            JObject deserialized = JObject.Parse(token);

            Assert.Equal("{\"enc\":\"A256GCM\"}",
                             UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])));

			Assert.True(deserialized["header"] is JObject);
			Assert.Equal("{\"alg\":\"RSA-OAEP-256\"}", deserialized["header"].ToString(Newtonsoft.Json.Formatting.None));

			Assert.True(deserialized["unprotected"] is JObject);
			Assert.Equal("{\"jku\":\"https://server.example.com/keys.jwks\"}", deserialized["unprotected"].ToString(Newtonsoft.Json.Formatting.None));

			Assert.Equal(16, ((string)deserialized["iv"]).Length); //IV size
            Assert.Equal(18, ((string)deserialized["ciphertext"]).Length); //cipher text size
            Assert.Equal(22, ((string)deserialized["tag"]).Length); //auth tag size
			
			Assert.Equal(Encoding.UTF8.GetString(JWE.Decrypt(token, PrivKey()).PlaintextBytes), payload);
		}

		[Fact]
		public void EncodeExtraProtectedHeaders()
        {
			var payload = "Hello World !";
			var extra = new Dictionary<string, object>
			{
				{ "jku", "https://server.example.com/keys.jwks" }
			};

			JweRecipient r = new JweRecipient(JweAlgorithm.RSA_OAEP_256, PubKey());

			string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, mode: SerializationMode.Json, extraProtectedHeaders: extra);

			Console.Out.WriteLine("[JSON][RSA_OAEP_256][A256GCM]: {0}", token);

            JObject deserialized = JObject.Parse(token);

            Assert.Equal("{\"enc\":\"A256GCM\",\"jku\":\"https://server.example.com/keys.jwks\"}",
                             UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])));

			Assert.True(deserialized["header"] is JObject);
			Assert.Equal("{\"alg\":\"RSA-OAEP-256\"}", deserialized["header"].ToString(Newtonsoft.Json.Formatting.None));

			Assert.Equal(16, ((string)deserialized["iv"]).Length); //IV size
            Assert.Equal(18, ((string)deserialized["ciphertext"]).Length); //cipher text size
            Assert.Equal(22, ((string)deserialized["tag"]).Length); //auth tag size
			
			Assert.Equal(Encoding.UTF8.GetString(JWE.Decrypt(token, PrivKey()).PlaintextBytes), payload);
		}

		[Fact]
		public void EncodeExtraRecipientHeaders()
		{
			var payload = "Hello World !";
			var extra = new Dictionary<string, object>
			{
				{ "kid", "2011-04-29" }
			};

			JweRecipient r = new JweRecipient(JweAlgorithm.RSA_OAEP_256, PubKey(), header: extra);

			string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, mode: SerializationMode.Json);

			Console.Out.WriteLine("[JSON][RSA_OAEP_256][A256GCM]: {0}", token);

			JObject deserialized = JObject.Parse(token);

			Assert.Equal("{\"enc\":\"A256GCM\"}",
							 UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])));

			Assert.True(deserialized["header"] is JObject);
			Assert.Equal("{\"alg\":\"RSA-OAEP-256\",\"kid\":\"2011-04-29\"}", deserialized["header"].ToString(Newtonsoft.Json.Formatting.None));

			Assert.Equal(16, ((string)deserialized["iv"]).Length); //IV size
			Assert.Equal(18, ((string)deserialized["ciphertext"]).Length); //cipher text size
			Assert.Equal(22, ((string)deserialized["tag"]).Length); //auth tag size

			Assert.Equal(Encoding.UTF8.GetString(JWE.Decrypt(token, PrivKey()).PlaintextBytes), payload);
		}

		[Fact]
		public void EncodeDuplicateHeaders_Protected_PerRecipient()
		{
			var payload = "Hello World !";
			var headers = new Dictionary<string, object>()
			{
				{ "enc", "A256GCM" }
			};			

			JweRecipient r = new JweRecipient(JweAlgorithm.RSA_OAEP_256, PubKey(), headers);			

			//then
			Assert.Throws<ArgumentException>(() => JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, mode: SerializationMode.Json));
		}

		[Fact]
		public void EncodeDuplicateHeaders_Protected_Unprotected()
		{
			var payload = "Hello World !";

			var unprotected = new Dictionary<string, object>
			{
				{ "enc", "A256GCM" }
			};

			JweRecipient r = new JweRecipient(JweAlgorithm.RSA_OAEP_256, PubKey());			

			//then
			Assert.Throws<ArgumentException>(() => JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, mode: SerializationMode.Json, unprotectedHeaders: unprotected));
		}

		[Fact]
		public void EncodeDuplicateHeaders_Unprotected_PerRecipient()
		{
			var payload = "Hello World !";
			var headers = new Dictionary<string, object>()
			{				
				{ "jku", "https://server.example.com/keys.jwks" }
			};

			var unprotected = new Dictionary<string, object>
			{
				{ "jku", "https://server.example.com/keys.jwks" }
			};


			JweRecipient r = new JweRecipient(JweAlgorithm.RSA_OAEP_256, PubKey(), headers);

			//then
			Assert.Throws<ArgumentException>(() => JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, mode: SerializationMode.Json, unprotectedHeaders: unprotected));
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

		private CngKey Ecc256Public()
		{
			byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
			byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
			byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

			return EccKey.New(x, y, usage: CngKeyUsages.KeyAgreement);
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
