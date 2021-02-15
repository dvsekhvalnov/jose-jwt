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
    }
}
