namespace UnitTests
{
    using Jose;
    using Jose.keys;
    using Microsoft.IdentityModel.Tokens;
    using Newtonsoft.Json.Linq;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using Xunit;
    using Xunit.Abstractions;

    public class JweUnixTest
    {
        private readonly TestConsole Console;

        public JweUnixTest(ITestOutputHelper output)
        {
            this.Console = new TestConsole(output);
        }

        [Theory]
        [InlineData(SerializationMode.Compact)]
        [InlineData(SerializationMode.Json)]
        public void EncryptDecrypt_RoundTripOneRecipient_PlaintextSurvives(SerializationMode mode)
        {
            //given
            byte[] payload = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            var recipients = new JweRecipient[]
            {
                recipientAes256KW1,
            };
            var sharedProtectedHeaders = new Dictionary<string, object>
            {
                { "cty", "application/octet-string"},
            };

            //when
            var jwe = JWE.EncryptBytes(
                plaintext: payload,
                recipients: recipients,
                JweEncryption.A256GCM,
                mode: mode,
                extraProtectedHeaders: sharedProtectedHeaders
            );

            var decrypted = JWE.Decrypt(jwe, aes256KWKey1);

            Console.Out.WriteLine("[{0}][A256GCM] = {1}", mode, jwe);

            //then
            Assert.Equal(payload, decrypted.PlaintextBytes);
        }

        public static IEnumerable<object[]> TestDataModeGeneralJsonRoundTripMultipleRecipients =>
            new List<object[]>
            {
                new object[] { aes256KWKey1 },
                new object[] { aes256KWKey2 },
                new object[] { PrivKey() },
            };

        [Theory]
        [MemberData(nameof(TestDataModeGeneralJsonRoundTripMultipleRecipients))]
        public void EncryptDecrypt_ModeGeneralJsonRoundTripMultipleRecipients_ValidRecipientsCanDecrypt(object decryptKey)
        {
            //given
            byte[] payload = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            var recipients = new JweRecipient[]
            {
                recipientAes256KW1,
                recipientAes256KW2,
                recipientRsa1,
            };
            var sharedProtectedHeaders = new Dictionary<string, object>
            {
                { "cty", "application/octet-string"},
            };

            //when
            var jwe = JWE.EncryptBytes(
                plaintext: payload,
                recipients: recipients,
                JweEncryption.A256GCM,
                extraProtectedHeaders: sharedProtectedHeaders
            );

            var decrypted = JWE.Decrypt(jwe, decryptKey);

            Console.Out.WriteLine("[Json][Multiple][A256GCM] = {0}", jwe);

            //then
            Assert.Equal(payload, decrypted.PlaintextBytes);
        }

        [Theory]
        [InlineData(JweEncryption.A256GCM, JweAlgorithm.ECDH_ES_A256KW, "The algorithm type passed to the Decrypt method did not match the algorithm type in the header.")]
        [InlineData(JweEncryption.A192GCM, JweAlgorithm.A256KW, "The encryption type passed to the Decrypt method did not match the encryption type in the header.")]
        public void Decrypt_MultipleRecipients_MismatchEncOrAlgThrows(JweEncryption expectedJweEnc, JweAlgorithm expectedJweAlg, string expectedMessage)
        {
            //given
            byte[] payload = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            var recipients = new JweRecipient[]
            {
                recipientAes256KW1,
                recipientAes256KW2,
                recipientRsa1,
            };
            var sharedProtectedHeaders = new Dictionary<string, object>
            {
                { "cty", "application/octet-string"},
            };
            var jwe = JWE.EncryptBytes(
                plaintext: payload,
                recipients: recipients,
                JweEncryption.A256GCM,
                extraProtectedHeaders: sharedProtectedHeaders
            );

            //when
            var exception = Record.Exception(() => JWE.Decrypt(jwe, aes256KWKey2, expectedJweAlg, expectedJweEnc));

            //then
            Assert.IsType<InvalidAlgorithmException>(exception);
            Assert.Equal(expectedMessage, exception.Message);
        }

        /// <summary>
        /// Attempting to decrypt with a private key not matching any of the recipients.
        /// </summary>
        [Fact]
        public void Decrypt_NoMatchingRecipient_Throws()
        {
            //given
            byte[] payload = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            var recipients = new JweRecipient[]
            {
                recipientAes256KW1,
                recipientAes256KW2,
            };
            var sharedProtectedHeaders = new Dictionary<string, object>
            {
                { "cty", "application/octet-string"},
            };
            var jwe = JWE.EncryptBytes(
                plaintext: payload,
                recipients: recipients,
                JweEncryption.A256GCM,
                extraProtectedHeaders: sharedProtectedHeaders
            );

            //when
            var exception = Record.Exception(() => { JWE.Decrypt(jwe, aes256KWKey3); });

            //then
            Assert.IsType<IntegrityException>(exception);
            Assert.Equal("AesKeyWrap integrity check failed.", exception.Message);
        }

        [Theory]
        [InlineData(SerializationMode.Compact, "Only one recipient is supported by the JWE Compact Serialization.")]
        public void Encrypt_WithMoreThanOneRecipient_Throws(SerializationMode mode, string expectedMessage)
        {
            //given
            byte[] plaintext = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            var recipients = new JweRecipient[]
            {
                recipientAes256KW1,
                recipientAes256KW2,
            };

            //when
            var exception = Record.Exception(() =>
                JWE.EncryptBytes(
                    plaintext: plaintext,
                    recipients: recipients,
                    JweEncryption.A256GCM,
                    mode: mode
                )
            );

            //then
            Assert.IsType<JoseException>(exception);
            Assert.Equal(expectedMessage, exception.Message);
        }

        [Fact]
        public void Encrypt_ModeCompactWithEmptyBytesA128KW_A128CBC_HS256_ExpectedResults()
        {
            //given
            byte[] plaintext = { };

            //when
            var jwe = JWE.EncryptBytes(
                plaintext: plaintext,
                recipients: new JweRecipient[] { recipientAes128KW },
                JweEncryption.A128CBC_HS256,
                mode: SerializationMode.Compact
            );

            //then
            Console.Out.WriteLine("Empty bytes A128KW_A128CBC_HS256 = {0}", jwe);

            string[] parts = jwe.Split('.');

            Assert.Equal(5, parts.Length); //Make sure 5 parts
            Assert.Equal("{\"alg\":\"A128KW\",\"enc\":\"A128CBC-HS256\"}",
                UTF8Encoding.UTF8.GetString(Base64Url.Decode(parts[0])));
            Assert.Equal("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", parts[0]); //Header is non-encrypted and static text
            Assert.Equal(54, parts[1].Length); //CEK size
            Assert.Equal(22, parts[2].Length); //IV size
            Assert.Equal(22, parts[3].Length); //cipher text size
            Assert.Equal(22, parts[4].Length); //auth tag size

            Assert.Equal(new byte[0], JWE.Decrypt(jwe, aes128KWKey).PlaintextBytes);
        }

        [Fact]
        public void Encrypt_ModeJsonTwoRecipientsWithEmptyBytesA128KW_A128CBC_HS256_ExpectedResults()
        {
            //given
            byte[] plaintext = { };

            //when
            var jwe = JWE.EncryptBytes(
                plaintext: plaintext,
                recipients: new JweRecipient[] { recipientAes128KW, recipientAes128KW },
                JweEncryption.A128CBC_HS256,
                mode: SerializationMode.Json
            );

            //then
            Console.Out.WriteLine("Empty bytes A128KW_A128CBC_HS256 (General Json Serialization) = {0}", jwe);

            JObject deserialized = JObject.Parse(jwe);

            Assert.Equal("{\"enc\":\"A128CBC-HS256\"}",
                 UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])));

            Assert.True(deserialized["recipients"] is JArray);
            Assert.Equal(2, ((JArray)deserialized["recipients"]).Count);

            var recipient0 = ((JArray)deserialized["recipients"])[0];

            Assert.True(recipient0["header"] is JObject);
            Assert.Equal("{\"alg\":\"A128KW\"}", recipient0["header"].ToString(Newtonsoft.Json.Formatting.None));
            Assert.Equal("A128KW", recipient0["header"]["alg"]);
            Assert.Equal(54, ((string)recipient0["encrypted_key"]).Length); //CEK size
            Assert.Equal(22, ((string)deserialized["iv"]).Length); //IV size
            Assert.Equal(22, ((string)deserialized["ciphertext"]).Length); //cipher text size
            Assert.Equal(22, ((string)deserialized["tag"]).Length); //auth tag size

            Assert.Equal(new byte[0], JWE.Decrypt(jwe, aes128KWKey).PlaintextBytes);
        }

        [Fact]
        public void Encrypt_ModeJsonOneRecipientWithEmptyBytesA128KW_A128CBC_HS256_ExpectedResults()
        {
            //given
            byte[] plaintext = { };

            //when
            var jwe = JWE.EncryptBytes(
                plaintext: plaintext,
                recipients: new JweRecipient[] { recipientAes128KW },
                JweEncryption.A128CBC_HS256
            );

            //then
            Console.Out.WriteLine("Empty bytes A128KW_A128CBC_HS256 (Flattened Json Serialization) = {0}", jwe);

            JObject deserialized = JObject.Parse(jwe);

            Assert.Equal("{\"enc\":\"A128CBC-HS256\"}",
                 UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])));

            Assert.True(deserialized["header"] is JObject);
            Assert.Equal("{\"alg\":\"A128KW\"}", deserialized["header"].ToString(Newtonsoft.Json.Formatting.None));
            Assert.Equal("A128KW", deserialized["header"]["alg"]);
            Assert.Equal(54, ((string)deserialized["encrypted_key"]).Length); //CEK size
            Assert.Equal(22, ((string)deserialized["iv"]).Length); //IV size
            Assert.Equal(22, ((string)deserialized["ciphertext"]).Length); //cipher text size
            Assert.Equal(22, ((string)deserialized["tag"]).Length); //auth tag size

            Assert.Equal(new byte[0], JWE.Decrypt(jwe, aes128KWKey).PlaintextBytes);
        }

        [Fact]
        public void Decrypt_Rfc7516AppendixA23DecryptWithFirstRecipient_ExpectedResults()
        {
            //given
            var key = GetLegacyKeyObjectFromJwk(new JsonWebKey(Rfc7516_A_2_3_ExampleJwk));

            //when
            var decrypted = JWE.Decrypt(Rfc7516_A_4_7_ExampleJwe, key);

            //then
            Assert.Equal("Live long and prosper.", decrypted.Plaintext);

            Assert.Equal(4, decrypted.Recipient.JoseHeader.Count);

            Assert.Equal("RSA1_5", decrypted.Recipient.JoseHeader["alg"]);
            Assert.Equal("2011-04-29", decrypted.Recipient.JoseHeader["kid"]);
            Assert.Equal("A128CBC-HS256", decrypted.Recipient.JoseHeader["enc"]);
            Assert.Equal("https://server.example.com/keys.jwks", decrypted.Recipient.JoseHeader["jku"]);
        }

        [Fact]
        public void Decrypt_Rfc7516AppendixA23DecryptWithSecondRecipient_ExpectedResults()
        {
            //given
            var key = GetLegacyKeyObjectFromJwk(new JsonWebKey(Rfc7516_A_3_3_ExampleJwk));

            //when
            var decrypted = JWE.Decrypt(Rfc7516_A_4_7_ExampleJwe, key);

            //then
            Assert.Equal("Live long and prosper.", decrypted.Plaintext);

            Assert.Equal(4, decrypted.Recipient.JoseHeader.Count);

            Assert.Equal("A128KW", decrypted.Recipient.JoseHeader["alg"]);
            Assert.Equal("7", decrypted.Recipient.JoseHeader["kid"]);
            Assert.Equal("A128CBC-HS256", decrypted.Recipient.JoseHeader["enc"]);
            Assert.Equal("https://server.example.com/keys.jwks", decrypted.Recipient.JoseHeader["jku"]);

            Assert.Null(decrypted.Aad);
        }

        [Fact]
        public void Encrypt_WithAdditionalAuthenticatedData_PopulatesAad()
        {
            //given
            var key = GetLegacyKeyObjectFromJwk(new JsonWebKey(Rfc7520_5_8_1_Figure151_ExampleJwk));

            //when
            var jwe = JWE.EncryptBytes(
                UTF8Encoding.UTF8.GetBytes(Rfc7520_Figure72_ExamplePlaintext),
                new JweRecipient[] { new JweRecipient(JweAlgorithm.A128KW, key) },
                JweEncryption.A128CBC_HS256,
                aad: Base64Url.Decode(Rfc7520_Figure176_ExampleBase64UrlEncodedAad)
            );

            //then
            JObject deserialized = JObject.Parse(jwe);

            var base64UrlAad = (string)deserialized["aad"];
            Assert.NotNull(base64UrlAad);
            Assert.Equal(Rfc7520_Figure176_ExampleBase64UrlEncodedAad, base64UrlAad);

            var decrypted = JWE.Decrypt(jwe, key);

            Assert.Equal(Rfc7520_Figure72_ExamplePlaintext, decrypted.Plaintext);
        }

        [Fact]
        public void EncryptDecrypt_WithAdditionalAuthenticatedData_RoundtripOk()
        {
            //given
            var key = GetLegacyKeyObjectFromJwk(new JsonWebKey(Rfc7520_5_8_1_Figure151_ExampleJwk));
            var plaintext = Rfc7520_Figure72_ExamplePlaintext;

            //when
            var jwe = JWE.EncryptBytes(
                UTF8Encoding.UTF8.GetBytes(Rfc7520_Figure72_ExamplePlaintext),
                new JweRecipient[] { new JweRecipient(JweAlgorithm.A128KW, key) },
                JweEncryption.A128CBC_HS256,
                aad: Base64Url.Decode(Rfc7520_Figure176_ExampleBase64UrlEncodedAad)
            );

            //then
            var decrypted = JWE.Decrypt(jwe, key);

            Assert.Equal(plaintext, decrypted.Plaintext);
        }

        [Fact]
        public void Decrypt_WithAdditionalAuthenticatedDataOk_ReturnsExpectedResults()
        {
            //given
            var jwk = new JsonWebKey(Rfc7520_5_8_1_Figure151_ExampleJwk);
            var key = GetLegacyKeyObjectFromJwk(jwk);
            var kid = jwk.Kid;

            //when
            var decrypted = JWE.Decrypt(Rfc7520_5_10_ExampleJwe, key);

            //then
            Assert.Equal(Rfc7520_Figure72_ExamplePlaintext, decrypted.Plaintext);

            Assert.Equal(3, decrypted.Recipient.JoseHeader.Count);

            Assert.Equal(jwk.Alg, decrypted.Recipient.JoseHeader["alg"]);
            Assert.Equal(jwk.Kid, decrypted.Recipient.JoseHeader["kid"]);
            Assert.Equal("A128GCM", decrypted.Recipient.JoseHeader["enc"]);

            Assert.Equal(Rfc7520_5_10_1_ExampleAadString, UTF8Encoding.UTF8.GetString(decrypted.Aad));
        }

        [Fact]
        public void Decrypt_WithAdditionalAuthenticatedDataTampered_Throws()
        {
            //given
            var key = GetLegacyKeyObjectFromJwk(new JsonWebKey(Rfc7520_5_8_1_Figure151_ExampleJwk));
            var tamperedJwe = Rfc7520_5_10_ExampleJwe.Replace("aad\": \"W", "aad\": \"V");

            //when
            var exception = Record.Exception(() => JWE.Decrypt(tamperedJwe, key));

            //then
            Assert.IsType<EncryptionException>(exception);
            Assert.Equal("Unable to decrypt content or authentication tag do not match.", exception.Message);
        }

        public static IEnumerable<object[]> TestDataMultipleRecipientDirectEncryption()
        {
            var ret = new List<object[]>
            {
                new object[] { new JweRecipient[] { recipientDirectEncyption1 }, null }, // (Single direct encryption is ok)
                new object[] { new JweRecipient[] { recipientDirectEncyption1, recipientAes256KW1 }, null }, // (Direct recipient currently allowed as first receipient)
                new object[] { new JweRecipient[] { recipientAes256KW1, recipientDirectEncyption1 }, "Direct Encryption not supported for multi-recipient JWE.", }, // (Direct recipient in multi not supported)
            };

            return ret;
        }

        [Theory]
        [MemberData(nameof(TestDataMultipleRecipientDirectEncryption))]
        public void Encrypt_MultipleRecipient_SpecialCasesHandled(JweRecipient[] recipients, string expectedError)
        {
            //given
            byte[] plaintext = { };

            //when
            var exception = Record.Exception(() =>
                JWE.EncryptBytes(
                    plaintext: plaintext,
                    recipients: recipients,
                    JweEncryption.A128CBC_HS256
                )
            );

            //then
            if (expectedError == null)
            {
                Assert.Null(exception);
            }
            else
            {
                Assert.IsType<JoseException>(exception);
                Assert.Equal(expectedError, exception.Message);
            }
        }

        /// <summary>
        /// Enforce uniquness of header names - as per https://tools.ietf.org/html/rfc7516#section-4
        /// Here passed into extraHeaders
        /// </summary>
        [Theory]
        [InlineData("example.com:extra_recipient_header")]
        [InlineData("alg")]
        [InlineData("enc")]
        public void Encrypt_WithNonUniqueHeaderParameterNamesInExtraHeaders_Throws(string injectedHeaderName)
        {
            //given
            byte[] plaintext = { };

            //when
            var exception = Record.Exception(() =>
                JWE.EncryptBytes(
                    plaintext: plaintext,
                    recipients: new JweRecipient[]
                    {
                        new JweRecipient(
                            JweAlgorithm.A256KW,
                            aes256KWKey1,
                            new Dictionary<string, object>
                            {
                                { "kid", "my_key_reference" },
                                { "example.com:extra_recipient_header", "value1" },
                            }
                        )
                    },
                    enc: JweEncryption.A128CBC_HS256,
                    extraProtectedHeaders: new Dictionary<string, object>
                    {
                        { "cty", "text/plain" },
                        { "example.com:extra_header", "another value" },
                        { injectedHeaderName, string.Empty },
                    }
                )
            );

            //then
            Assert.NotNull(exception);
            Assert.IsType<ArgumentException>(exception);
            Assert.StartsWith("An item with the same key has already been added.", exception.Message);
        }

        /// <summary>
        /// Enforce uniquness of header names - as per https://tools.ietf.org/html/rfc7516#section-4
        /// Here passed into recipient's headers
        /// </summary>
        [Theory]
        [InlineData("example.com:extra_header")]
        [InlineData("alg")]
        [InlineData("enc")]
        public void Encrypt_WithNonUniqueHeaderParameterNamesInRecipientHeaders_Throws(string injectedHeaderName)
        {
            //given
            byte[] plaintext = { };

            //when
            var exception = Record.Exception(() =>
                JWE.EncryptBytes(
                    plaintext: plaintext,
                    recipients: new JweRecipient[]
                    {
                        new JweRecipient(
                            JweAlgorithm.A256KW,
                            aes256KWKey1,
                            new Dictionary<string, object>
                            {
                                { "kid", "my_key_reference" },
                                { "example.com:extra_recipient_header", "value1" },
                                { injectedHeaderName, string.Empty },
                            })
                    },
                    enc: JweEncryption.A128CBC_HS256,
                    extraProtectedHeaders: new Dictionary<string, object>
                    {
                        { "cty", "text/plain" },
                        { "example.com:extra_header", "another value" },
                    }
                )
            );

            //then
            Assert.NotNull(exception);
            Assert.IsType<ArgumentException>(exception);
            Assert.StartsWith("An item with the same key has already been added.", exception.Message);
        }

        [Fact]
        public void UnsafeJoseHeaders_ModeCompactWithEmptyBytesA128KW_A128CBC_HS256_ExpectedResults()
        {
            //given
            byte[] plaintext = { };
            var jwe = JWE.EncryptBytes(
                plaintext: plaintext,
                recipients: new JweRecipient[] { recipientAes128KW },
                JweEncryption.A128CBC_HS256,
                mode: SerializationMode.Compact
            );

            //when
            var test = JWE.Headers(jwe);

            //then
            Assert.Single(test.Recipients);

            Assert.Equal(2, test.Recipients[0].JoseHeader.Count);
            Assert.Equal("A128CBC-HS256", test.Recipients[0].JoseHeader["enc"]);
            Assert.Equal("A128KW", test.Recipients[0].JoseHeader["alg"]);
        }

        [Fact]
        public void UnsafeJoseHeaders_Rfc7516AppendixA23_ExpectedResults()
        {
            //when
            var test = JWE.Headers(Rfc7516_A_4_7_ExampleJwe);

            //then
            Assert.Equal(2, test.Recipients.Count);

            Assert.Equal(4, test.Recipients[0].JoseHeader.Count);
            Assert.Equal("A128CBC-HS256", test.Recipients[0].JoseHeader["enc"]);
            Assert.Equal("https://server.example.com/keys.jwks", test.Recipients[0].JoseHeader["jku"]);
            Assert.Equal("RSA1_5", test.Recipients[0].JoseHeader["alg"]);
            Assert.Equal("2011-04-29", test.Recipients[0].JoseHeader["kid"]);

            Assert.Equal(4, test.Recipients[1].JoseHeader.Count);
            Assert.Equal("A128CBC-HS256", test.Recipients[1].JoseHeader["enc"]);
            Assert.Equal("https://server.example.com/keys.jwks", test.Recipients[1].JoseHeader["jku"]);
            Assert.Equal("A128KW", test.Recipients[1].JoseHeader["alg"]);
            Assert.Equal("7", test.Recipients[1].JoseHeader["kid"]);
        }

        [Fact]
        public void DecodeSingleRecipientProtectedHeader()
        {
            var token = @"{""ciphertext"":""tzh1xXdNDke99sLmZEnmYw"",""encrypted_key"":""DNszn45AFTiUAWsPeLi-AZd4oSkUKLK95FrRMpDv9qEe9TIA6QOPezOh7NrOzTXa8AdrbnDRQJwO7S_0i4p5xQrEukjkzelD"",""header"":{""alg"":""A256KW"",""enc"":""A256CBC-HS512""},""iv"":""480QxkaQPCiaEmxJFPxgsg"",""tag"":""dHeG5UCb4nCSbysUKva_4I_Z4D2WfYUaeasxOsJXTYg""}";

            var payload = Jose.JWE.Decrypt(token, sharedKey);

            Assert.Equal("Hello World", payload.Plaintext);

            Assert.Equal(2, payload.Recipient.JoseHeader.Count);
            Assert.Equal("A256CBC-HS512", payload.Recipient.JoseHeader["enc"]);
            Assert.Equal("A256KW", payload.Recipient.JoseHeader["alg"]);
        }

        [Fact]
        public void DecodeAAD()
        {
            var token = @"{""aad"":""ZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4w"",""ciphertext"":""02VvoX1sUsmFi2ZpIbTI8g"",""encrypted_key"":""kH4te-O3DNZoDlxeDnBXM9CNx2d5IgVGO-cVMmqTRW_ws0EG_RKDQ7FLLztMM83z2s-pSNSZtFf3bx9Aky8XOzhIYCIU7XvmiQ0pp5z1FRdrwO-RxEOJfb2hAjD-hE5lCJkkY722QGs4IrUQ5N5Atc9h9-0vDcg-gksFIuaLMeRQj3LxivhwJO-QWFd6sG0FY6fBCwS1X6zsrZo-m9DNvrB6FhMpkLPBDOlCNnjKf1_Mz_jAuXIwnVUhoq59m8tvxQY1Fyngiug6zSnM207-0BTXzuCTnPgPAwGWGDLO7o0ttPT6RI_tLvYE6AuOynsqsHDaecyIkJ26dif3iRmkeg"",""header"":{""alg"":""RSA-OAEP-256"",""kid"":""Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc""},""iv"":""E1BAiqIeAH_0eInT59zb8w"",""protected"":""eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldFIn0"",""tag"":""yYBiajF5oMtyK3mRVQyPnlJL25hXW8Ct8ZMcFK5ehDY""}";

            var payload = Jose.JWE.Decrypt(token, PrivKey());

            Assert.Equal("Hello World", payload.Plaintext);

            Assert.Equal(4, payload.Recipient.JoseHeader.Count);
            Assert.Equal("A256CBC-HS512", payload.Recipient.JoseHeader["enc"]);
            Assert.Equal("RSA-OAEP-256", payload.Recipient.JoseHeader["alg"]);
            Assert.Equal("Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc", payload.Recipient.JoseHeader["kid"]);
            Assert.Equal("JWE", payload.Recipient.JoseHeader["typ"]);
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

            Assert.Equal(2, firstRecipient.Recipient.JoseHeader.Count);
            Assert.Equal("A256GCM", firstRecipient.Recipient.JoseHeader["enc"]);
            Assert.Equal("A256KW", firstRecipient.Recipient.JoseHeader["alg"]);

            var secondRecipient = Jose.JWE.Decrypt(token, PrivKey());

            Assert.Equal("Hello World", secondRecipient.Plaintext);

            Assert.Equal(3, secondRecipient.Recipient.JoseHeader.Count);
            Assert.Equal("A256GCM", secondRecipient.Recipient.JoseHeader["enc"]);
            Assert.Equal("JWE", secondRecipient.Recipient.JoseHeader["typ"]);
            Assert.Equal("RSA-OAEP-256", secondRecipient.Recipient.JoseHeader["alg"]);
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

            Assert.Equal(3, firstRecipient.Recipient.JoseHeader.Count);
            Assert.Equal("A256CBC-HS512", firstRecipient.Recipient.JoseHeader["enc"]);
            Assert.Equal("JWE", firstRecipient.Recipient.JoseHeader["typ"]);
            Assert.Equal("A256KW", firstRecipient.Recipient.JoseHeader["alg"]);

            var secondRecipient = Jose.JWE.Decrypt(token, PrivKey());

            Assert.Equal("Hello World", secondRecipient.Plaintext);

            Assert.Equal(4, secondRecipient.Recipient.JoseHeader.Count);
            Assert.Equal("A256CBC-HS512", secondRecipient.Recipient.JoseHeader["enc"]);
            Assert.Equal("JWE", secondRecipient.Recipient.JoseHeader["typ"]);
            Assert.Equal("RSA-OAEP-256", secondRecipient.Recipient.JoseHeader["alg"]);
            Assert.Equal("Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc", secondRecipient.Recipient.JoseHeader["kid"]);
        }

        [SkippableFact]
        public void DecodeMultipleRecipientsWithUnprotectedHeader()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "This requires CNG, which is Windows Only.");

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

            Assert.Equal(5, firstRecipient.Recipient.JoseHeader.Count);
            Assert.Equal("A256CBC-HS512", firstRecipient.Recipient.JoseHeader["enc"]);
            Assert.Equal("JWE", firstRecipient.Recipient.JoseHeader["typ"]);
            Assert.Equal("PBES2-HS256+A128KW", firstRecipient.Recipient.JoseHeader["alg"]);
            Assert.Equal(8192L, firstRecipient.Recipient.JoseHeader["p2c"]);
            Assert.Equal("kpL8s71MjhPnBExCF-cIMA", firstRecipient.Recipient.JoseHeader["p2s"]);

            var secondRecipient = Jose.JWE.Decrypt(token, Ecc256Private());

            Assert.Equal("Hello World", secondRecipient.Plaintext);

            Assert.Equal(4, secondRecipient.Recipient.JoseHeader.Count);
            Assert.Equal("A256CBC-HS512", secondRecipient.Recipient.JoseHeader["enc"]);
            Assert.Equal("JWE", secondRecipient.Recipient.JoseHeader["typ"]);
            Assert.Equal("ECDH-ES+A128KW", secondRecipient.Recipient.JoseHeader["alg"]);
            Assert.True(secondRecipient.Recipient.JoseHeader.ContainsKey("epk"));

            var epk = (IDictionary<string, object>)secondRecipient.Recipient.JoseHeader["epk"];
            Assert.Equal(4, epk.Count);
            Assert.Equal("P-256", epk["crv"]);
            Assert.Equal("EC", epk["kty"]);
            Assert.Equal("WOqJxZwzivLSO-r3qRkBVDd9uA_de_AIu3G3hkIQg1M", epk["x"]);
            Assert.Equal("aFbCEl231v5IeA_Zjg8kMVJXxZWhpEHibtvHnq7Kk9k", epk["y"]);
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

        [SkippableFact]
        public void DecodeDuplicateKeys_UnprotectedHeader_RecipientHeader()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "This requires CNG, which is Windows Only.");

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

            string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM);

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
            Assert.Equal(payload, decoded.Plaintext);
        }

        [Fact]
        public void EncodeWithAAD()
        {
            var payload = "Hello World !";
            JweRecipient r = new JweRecipient(JweAlgorithm.A256KW, sharedKey);

            var aad = new byte[] { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48 };

            string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, aad);

            Console.Out.WriteLine("[JSON][A256KW][A256GCM][AAD]: {0}", token);

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
            Assert.Equal(payload, decoded.Plaintext);
        }

        [SkippableFact]
        public void EncodeMultipleRecipients()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "This requires CNG, which is Windows Only.");

            var payload = "Hello World !";
            JweRecipient r1 = new JweRecipient(JweAlgorithm.PBES2_HS256_A128KW, "secret");
            JweRecipient r2 = new JweRecipient(JweAlgorithm.ECDH_ES_A128KW, Ecc256Public());
            JweRecipient r3 = new JweRecipient(JweAlgorithm.RSA_OAEP_256, PubKey());

            string token = JWE.Encrypt(payload, new[] { r1, r2, r3 }, JweEncryption.A256GCM);

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
            Assert.Equal(8192L, rec0["header"]["p2c"]);
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

            Assert.Equal(payload, JWE.Decrypt(token, "secret").Plaintext);
            Assert.Equal(payload, JWE.Decrypt(token, PrivKey()).Plaintext);
            Assert.Equal(payload, JWE.Decrypt(token, Ecc256Private()).Plaintext);
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

            string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, unprotectedHeaders: unprotected);

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

            Assert.Equal(payload, Encoding.UTF8.GetString(JWE.Decrypt(token, PrivKey()).PlaintextBytes));
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

            string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, extraProtectedHeaders: extra);

            Console.Out.WriteLine("[JSON][RSA_OAEP_256][A256GCM]: {0}", token);

            JObject deserialized = JObject.Parse(token);

            Assert.Equal("{\"enc\":\"A256GCM\",\"jku\":\"https://server.example.com/keys.jwks\"}",
                             UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])));

            Assert.True(deserialized["header"] is JObject);
            Assert.Equal("{\"alg\":\"RSA-OAEP-256\"}", deserialized["header"].ToString(Newtonsoft.Json.Formatting.None));

            Assert.Equal(16, ((string)deserialized["iv"]).Length); //IV size
            Assert.Equal(18, ((string)deserialized["ciphertext"]).Length); //cipher text size
            Assert.Equal(22, ((string)deserialized["tag"]).Length); //auth tag size

            Assert.Equal(payload, Encoding.UTF8.GetString(JWE.Decrypt(token, PrivKey()).PlaintextBytes));
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

            string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM);

            Console.Out.WriteLine("[JSON][RSA_OAEP_256][A256GCM]: {0}", token);

            JObject deserialized = JObject.Parse(token);

            Assert.Equal("{\"enc\":\"A256GCM\"}",
                             UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])));

            Assert.True(deserialized["header"] is JObject);
            Assert.Equal("{\"alg\":\"RSA-OAEP-256\",\"kid\":\"2011-04-29\"}", deserialized["header"].ToString(Newtonsoft.Json.Formatting.None));

            Assert.Equal(16, ((string)deserialized["iv"]).Length); //IV size
            Assert.Equal(18, ((string)deserialized["ciphertext"]).Length); //cipher text size
            Assert.Equal(22, ((string)deserialized["tag"]).Length); //auth tag size

            Assert.Equal(payload, Encoding.UTF8.GetString(JWE.Decrypt(token, PrivKey()).PlaintextBytes));
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
            Assert.Throws<ArgumentException>(() => JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM));
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
            Assert.Throws<ArgumentException>(() => JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, unprotectedHeaders: unprotected));
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
            Assert.Throws<ArgumentException>(() => JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, unprotectedHeaders: unprotected));
        }

        private static object GetLegacyKeyObjectFromJwk(JsonWebKey jwk)
        {
            switch (jwk.Kty)
            {
                case "RSA":
                    var rsa = RSA.Create();
                    rsa.ImportParameters(new RSAParameters()
                    {
                        Modulus = Base64Url.Decode(jwk.N),
                        Exponent = Base64Url.Decode(jwk.E),
                        D = Base64Url.Decode(jwk.D),
                        P = Base64Url.Decode(jwk.P),
                        Q = Base64Url.Decode(jwk.Q),
                        DP = Base64Url.Decode(jwk.DP),
                        DQ = Base64Url.Decode(jwk.DQ),
                        InverseQ = Base64Url.Decode(jwk.QI),
                    });
                    return rsa;

                case "oct":
                    return Base64Url.Decode(jwk.K);

                default:
                    throw new NotImplementedException($"Key type not implemented: {jwk.Kty}");
            }
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

        private static ECDiffieHellman Ecc256Public()
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EccKeyUnix.New(x, y, usage: CngKeyUsages.KeyAgreement);
        }

        private static ECDiffieHellman Ecc256Private()
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EccKeyUnix.New(x, y, d, CngKeyUsages.KeyAgreement);
        }

        private static readonly byte[] sharedKey = new byte[] { 21, 26, 196, 88, 134, 11, 137, 127, 215, 118, 142, 180, 138, 115, 246, 247, 179, 182, 140, 136, 76, 33, 206, 189, 255, 22, 243, 100, 251, 74, 254, 161 };

        private static readonly byte[] aes256KWKey1 = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, };

        private static readonly byte[] aes256KWKey2 = new byte[] { 94, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, };

        private static readonly byte[] aes256KWKey3 = new byte[] { 4, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, };

        private static readonly byte[] aes128KWKey = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };

        private static JweRecipient recipientEcdhEs1 => new JweRecipient(JweAlgorithm.ECDH_ES, Ecc256Public());

        private static JweRecipient recipientAes256KW1 => new JweRecipient(JweAlgorithm.A256KW, aes256KWKey1);

        private static JweRecipient recipientAes256KW2 => new JweRecipient(JweAlgorithm.A256KW, aes256KWKey2);

        private static JweRecipient recipientAes128KW => new JweRecipient(JweAlgorithm.A128KW, aes128KWKey);

        private static JweRecipient recipientDirectEncyption1 => new JweRecipient(JweAlgorithm.DIR, aes256KWKey1);

        private static JweRecipient recipientRsa1 => new JweRecipient(JweAlgorithm.RSA1_5, PubKey());

        private const string Rfc7516_A_4_7_ExampleJwe = @"
        {
        ""protected"":
            ""eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"",
        ""unprotected"":
            { ""jku"":""https://server.example.com/keys.jwks""},
        ""recipients"":[
            {""header"":
                { ""alg"":""RSA1_5"",""kid"":""2011-04-29""},
            ""encrypted_key"":
                ""UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A""},
            {""header"":
                { ""alg"":""A128KW"",""kid"":""7""},
            ""encrypted_key"":
                ""6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ""}],
        ""iv"":
            ""AxY8DCtDaGlsbGljb3RoZQ"",
        ""ciphertext"":
            ""KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"",
        ""tag"":
            ""Mz-VPPyU4RlcuYv1IwIvzw""
        }";

        private const string Rfc7516_A_2_3_ExampleJwk = @"
            {""kty"":""RSA"",
                ""n"":""sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw"",
                ""e"":""AQAB"",
                ""d"":""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
                ""p"":""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
                ""q"":""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
                ""dp"":""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
                ""dq"":""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
                ""qi"":""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
            }";

        private const string Rfc7516_A_3_3_ExampleJwk = @"
            {""kty"":""oct"",
            ""k"":""GawgguFyGrWKav7AX4VKUg""
            }";

        private const string Rfc7520_5_10_ExampleJwe = @"
            {
             ""recipients"": [
               {
                 ""encrypted_key"": ""4YiiQ_ZzH76TaIkJmYfRFgOV9MIpnx4X""
               }
             ],
             ""protected"": ""eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0"",
             ""iv"": ""veCx9ece2orS7c_N"",
             ""aad"": ""WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxbImZuIix7fSwidGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4iLHt9LCJ0ZXh0IixbIkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIsIiJdXSxbImJkYXkiLHt9LCJ0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVyIix7fSwidGV4dCIsIk0iXV1d"",
             ""ciphertext"": ""Z_3cbr0k3bVM6N3oSNmHz7Lyf3iPppGf3Pj17wNZqteJ0Ui8p74SchQP8xygM1oFRWCNzeIa6s6BcEtp8qEFiqTUEyiNkOWDNoF14T_4NFqF-p2Mx8zkbKxI7oPK8KNarFbyxIDvICNqBLba-v3uzXBdB89fzOI-Lv4PjOFAQGHrgv1rjXAmKbgkft9cB4WeyZw8MldbBhc-V_KWZslrsLNygon_JJWd_ek6LQn5NRehvApqf9ZrxB4aq3FXBxOxCys35PhCdaggy2kfUfl2OkwKnWUbgXVD1C6HxLIlqHhCwXDG59weHrRDQeHyMRoBljoV3X_bUTJDnKBFOod7nLz-cj48JMx3SnCZTpbQAkFV"",
             ""tag"": ""vOaH_Rajnpy_3hOtqvZHRA""
           }";

        private const string Rfc7520_5_8_1_Figure151_ExampleJwk = @"
            {
             ""kty"": ""oct"",
             ""kid"": ""81b20965-8332-43d9-a468-82160ad91ac8"",
             ""use"": ""enc"",
             ""alg"": ""A128KW"",
             ""k"": ""GZy6sIZ6wl9NJOKB-jnmVQ""
            }";

        private const string Rfc7520_Figure72_ExamplePlaintext =
               "You can trust us to stick with you through thick and "
               + "thin\x2013to the bitter end. And you can trust us to "
               + "keep any secret of yours\x2013closer than you keep it "
               + "yourself. But you cannot trust us to let you face trouble "
               + "alone, and go off without a word. We are your friends, Frodo.";

        private const string Rfc7520_Figure176_ExampleBase64UrlEncodedAad =
            "WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxbImZuIix7fS"
               + "widGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4iLHt9LCJ0ZXh0Iixb"
               + "IkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIsIiJdXSxbImJkYXkiLHt9LC"
               + "J0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVyIix7fSwidGV4dCIsIk0iXV1d";

        private const string Rfc7520_5_10_1_ExampleAadString =
            "[\"vcard\",[[\"version\",{},\"text\",\"4.0\"],[\"fn\",{},\"text\",\"Meriadoc Brandybuck\"],[\"n\",{},\"text\",[\"Brandybuck\",\"Meriadoc\",\"Mr.\",\"\"]],[\"bday\",{},\"text\",\"TA 2982\"],[\"gender\",{},\"text\",\"M\"]]]";
    }
}