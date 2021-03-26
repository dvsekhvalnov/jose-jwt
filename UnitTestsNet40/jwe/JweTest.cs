namespace UnitTests
{
    using Jose;
    using Jose.keys;
    using Newtonsoft.Json.Linq;
    using System;
    using System.Collections.Generic;
    using System.Linq;    
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
	using NUnit.Framework;
    using Newtonsoft.Json;

    [TestFixture]
    public class JweTest
    {
		static object[][] SerializationModes = new object[][]
		{
		    new object[]{ SerializationMode.Compact },
		    new object[]{ SerializationMode.Json }
		};
		
		[Test, TestCaseSource("SerializationModes")]
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
                extraProtectedHeaders: sharedProtectedHeaders);

            var decrypted = JWE.Decrypt(jwe, aes256KWKey1);

            Console.Out.WriteLine("[{0}][A256GCM] = {1}", mode, jwe);

            //then
            Assert.That(decrypted.PlaintextBytes, Is.EqualTo(payload));
        }


		static IEnumerable<object> TestDataModeGeneralJsonRoundTripMultipleRecipients 
		{
            get {
                yield return aes256KWKey1;
                yield return aes256KWKey2;
                yield return PrivKey();
            }
		}        

		[Test, TestCaseSource(nameof(TestDataModeGeneralJsonRoundTripMultipleRecipients))]			
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
                extraProtectedHeaders: sharedProtectedHeaders);

            var decrypted = JWE.Decrypt(jwe, decryptKey);

            Console.Out.WriteLine("[Json][Multiple][A256GCM] = {0}", jwe);

            //then
            Assert.That(decrypted.PlaintextBytes, Is.EqualTo(payload));
        }

		static object[] MultipleRecipients = new object[]
		{
		    new object[]{ JweEncryption.A256GCM, JweAlgorithm.ECDH_ES_A256KW, "The algorithm type passed to the Decrypt method did not match the algorithm type in the header." },
		    new object[]{ JweEncryption.A192GCM, JweAlgorithm.A256KW, "The encryption type passed to the Decrypt method did not match the encryption type in the header." }
		};

		[Test, TestCaseSource("MultipleRecipients")]			
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
                extraProtectedHeaders: sharedProtectedHeaders);

            //when
            var exception = Assert.Throws<InvalidAlgorithmException>(delegate {
                JWE.Decrypt(jwe, aes256KWKey2, expectedJweAlg, expectedJweEnc); 
            });

            //then            
            Assert.That(exception.Message, Is.EqualTo(expectedMessage));
        }

        /// <summary>
        /// Attempting to decrypt with a private key not matching any of the recipients.
        /// </summary>
        [Test]
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
                extraProtectedHeaders: sharedProtectedHeaders);

            //when
            var exception = Assert.Throws<IntegrityException>( delegate 
            { 
                JWE.Decrypt(jwe, aes256KWKey3); 
            });

            //then
            Assert.That(exception.Message, Is.EqualTo("AesKeyWrap integrity check failed."));
        }

		[Test]
        public void Encrypt_WithMoreThanOneRecipient_Throws()
        {
            //given
            byte[] plaintext = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            var recipients = new JweRecipient[]
            {
                recipientAes256KW1,
                recipientAes256KW2,
            };

            //when
            var exception = Assert.Throws<JoseException>(delegate
            {
                JWE.EncryptBytes(
                  plaintext: plaintext,
                  recipients: recipients,
                  JweEncryption.A256GCM,
                  mode: SerializationMode.Compact);
            });

            //then            
            Assert.That(exception.Message, Is.EqualTo("Only one recipient is supported by the JWE Compact Serialization."));
        }

        [Test]
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

            Assert.That(parts.Length, Is.EqualTo(5)); //Make sure 5 parts
            Assert.That(UTF8Encoding.UTF8.GetString(Base64Url.Decode(parts[0])), Is.EqualTo("{\"alg\":\"A128KW\",\"enc\":\"A128CBC-HS256\"}"));
            Assert.That(parts[0], Is.EqualTo("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0")); //Header is non-encrypted and static text
            Assert.That(parts[1].Length, Is.EqualTo(54)); //CEK size
            Assert.That(parts[2].Length, Is.EqualTo(22)); //IV size
            Assert.That(parts[3].Length, Is.EqualTo(22)); //cipher text size
            Assert.That(parts[4].Length, Is.EqualTo(22)); //auth tag size

            Assert.That(JWE.Decrypt(jwe, aes128KWKey).PlaintextBytes, Is.EqualTo(new byte[0]));
        }

        [Test]
        public void Encrypt_ModeJsonTwoRecipientsWithEmptyBytesA128KW_A128CBC_HS256_ExpectedResults()
        {
            //given
            byte[] plaintext = { };

            //when
            var jwe = JWE.EncryptBytes(
                plaintext: plaintext,
                recipients: new JweRecipient[] { recipientAes128KW, recipientAes128KW },
                JweEncryption.A128CBC_HS256
            );

            //then
            Console.Out.WriteLine("Empty bytes A128KW_A128CBC_HS256 (General Json Serialization) = {0}", jwe);

            JObject deserialized = JObject.Parse(jwe);

            Assert.That(UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])), Is.EqualTo("{\"enc\":\"A128CBC-HS256\"}"));

            Assert.True(deserialized["recipients"] is JArray);
            Assert.That(((JArray)deserialized["recipients"]).Count, Is.EqualTo(2));

            var recipient0 = ((JArray)deserialized["recipients"])[0];

            Assert.True(recipient0["header"] is JObject);
            Assert.That(recipient0["header"].ToString(Newtonsoft.Json.Formatting.None), Is.EqualTo("{\"alg\":\"A128KW\"}"));
            Assert.That((string)recipient0["header"]["alg"], Is.EqualTo("A128KW"));
            Assert.That(((string)recipient0["encrypted_key"]).Length, Is.EqualTo(54)); //CEK size
            Assert.That(((string)deserialized["iv"]).Length, Is.EqualTo(22)); //IV size
            Assert.That(((string)deserialized["ciphertext"]).Length, Is.EqualTo(22)); //cipher text size
            Assert.That(((string)deserialized["tag"]).Length, Is.EqualTo(22)); //auth tag size

            Assert.That(JWE.Decrypt(jwe, aes128KWKey).PlaintextBytes, Is.EqualTo(new byte[0]));
        }

        [Test]
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

            Assert.That(UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])), Is.EqualTo("{\"enc\":\"A128CBC-HS256\"}"));

            Assert.True(deserialized["header"] is JObject);
            Assert.That(deserialized["header"].ToString(Newtonsoft.Json.Formatting.None), Is.EqualTo("{\"alg\":\"A128KW\"}"));
            Assert.That((string)deserialized["header"]["alg"], Is.EqualTo("A128KW"));
            Assert.That(((string)deserialized["encrypted_key"]).Length, Is.EqualTo(54)); //CEK size
            Assert.That(((string)deserialized["iv"]).Length, Is.EqualTo(22)); //IV size
            Assert.That(((string)deserialized["ciphertext"]).Length, Is.EqualTo(22)); //cipher text size
            Assert.That(((string)deserialized["tag"]).Length, Is.EqualTo(22)); //auth tag size

            Assert.That(JWE.Decrypt(jwe, aes128KWKey).PlaintextBytes, Is.EqualTo(new byte[0]));
        }

        [Test]
        public void Decrypt_Rfc7516AppendixA23DecryptWithFirstRecipient_ExpectedResults()
        {
            //given
            var key = GetLegacyKeyObjectFromJwk(Rfc7516_A_2_3_ExampleJwk);

            //when
            var decrypted = JWE.Decrypt(Rfc7516_A_4_7_ExampleJwe, key);

            //then
            Assert.That(decrypted.Plaintext, Is.EqualTo("Live long and prosper."));

            Assert.That(decrypted.Recipient.JoseHeader.Count, Is.EqualTo(4));

            Assert.That(decrypted.Recipient.JoseHeader["alg"], Is.EqualTo("RSA1_5"));
            Assert.That(decrypted.Recipient.JoseHeader["kid"], Is.EqualTo("2011-04-29"));
            Assert.That(decrypted.Recipient.JoseHeader["enc"], Is.EqualTo("A128CBC-HS256"));
            Assert.That(decrypted.Recipient.JoseHeader["jku"], Is.EqualTo("https://server.example.com/keys.jwks"));
        }

        [Test]
        public void Decrypt_Rfc7516AppendixA23DecryptWithSecondRecipient_ExpectedResults()
        {
            //given
            var key = GetLegacyKeyObjectFromJwk(Rfc7516_A_3_3_ExampleJwk);

            //when
            var decrypted = JWE.Decrypt(Rfc7516_A_4_7_ExampleJwe, key);

            //then
            Assert.That(decrypted.Plaintext, Is.EqualTo("Live long and prosper."));

            Assert.That(decrypted.Recipient.JoseHeader.Count, Is.EqualTo(4));

            Assert.That(decrypted.Recipient.JoseHeader["alg"], Is.EqualTo("A128KW"));
            Assert.That(decrypted.Recipient.JoseHeader["kid"], Is.EqualTo("7"));
            Assert.That(decrypted.Recipient.JoseHeader["enc"], Is.EqualTo("A128CBC-HS256"));
            Assert.That(decrypted.Recipient.JoseHeader["jku"], Is.EqualTo("https://server.example.com/keys.jwks"));

            Assert.Null(decrypted.Aad);
        }

        [Test]
        public void Encrypt_WithAdditionalAuthenticatedData_PopulatesAad()
        {
            //given
            var key = GetLegacyKeyObjectFromJwk(Rfc7520_5_8_1_Figure151_ExampleJwk);            

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
            Assert.That(base64UrlAad, Is.EqualTo(Rfc7520_Figure176_ExampleBase64UrlEncodedAad));

            var decrypted = JWE.Decrypt(jwe, key);

            Assert.That(decrypted.Plaintext, Is.EqualTo(Rfc7520_Figure72_ExamplePlaintext));
        }

        [Test]
        public void EncryptDecrypt_WithAdditionalAuthenticatedData_RoundtripOk()
        {            
            //given
            var key = GetLegacyKeyObjectFromJwk(Rfc7520_5_8_1_Figure151_ExampleJwk);
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

            Assert.That(decrypted.Plaintext, Is.EqualTo(plaintext));
        }        

        [Test]
        public void Decrypt_WithAdditionalAuthenticatedDataOk_ReturnsExpectedResults()
        {
            //given            
            var key = GetLegacyKeyObjectFromJwk(Rfc7520_5_8_1_Figure151_ExampleJwk);            

            //when
            var decrypted = JWE.Decrypt(Rfc7520_5_10_ExampleJwe, key);

            //then
            Assert.That(decrypted.Plaintext, Is.EqualTo(Rfc7520_Figure72_ExamplePlaintext));

            Assert.That(decrypted.Recipient.JoseHeader.Count, Is.EqualTo(3));

            Assert.That(decrypted.Recipient.JoseHeader["alg"], Is.EqualTo("A128KW"));
            Assert.That(decrypted.Recipient.JoseHeader["kid"], Is.EqualTo("81b20965-8332-43d9-a468-82160ad91ac8"));
            Assert.That(decrypted.Recipient.JoseHeader["enc"], Is.EqualTo("A128GCM"));

            Assert.That(UTF8Encoding.UTF8.GetString(decrypted.Aad), Is.EqualTo(Rfc7520_5_10_1_ExampleAadString));
        }

        [Test]
        public void Decrypt_WithAdditionalAuthenticatedDataTampered_Throws()
        {
            //given
            var key = GetLegacyKeyObjectFromJwk(Rfc7520_5_8_1_Figure151_ExampleJwk);
            var tamperedJwe = Rfc7520_5_10_ExampleJwe.Replace("aad\": \"W", "aad\": \"V");

            //when
            var exception = Assert.Throws<EncryptionException>(delegate {
                JWE.Decrypt(tamperedJwe, key); 
            });

            //then            
            Assert.That(exception.Message, Is.EqualTo("Unable to decrypt content or authentication tag do not match."));
        }

        static IEnumerable<TestCaseData> TestDataMultipleRecipientDirectEncryption
        {
            get
            {
                yield return new TestCaseData(new JweRecipient[] { recipientDirectEncyption1 }, null ); // (Single direct encryption is ok)
                yield return new TestCaseData(new JweRecipient[] { recipientDirectEncyption1, recipientAes256KW1 }, null); // (Direct recipient currently allowed as first receipient)
                yield return new TestCaseData(new JweRecipient[] { recipientAes256KW1, recipientDirectEncyption1 }, "Direct Encryption not supported for multi-recipient JWE."); // (Direct recipient in multi not supported)
            }
        }

        [Test, TestCaseSource(nameof(TestDataMultipleRecipientDirectEncryption))]
        public void Encrypt_MultipleRecipient_SpecialCasesHandled(JweRecipient[] recipients, string expectedError)
        {
            //given
            byte[] plaintext = { };

            //when
            Exception exception = null;
            
            try 
            {
                JWE.EncryptBytes(
                plaintext: plaintext,
                recipients: recipients,
                JweEncryption.A128CBC_HS256);
            }
            catch(JoseException e)
            {
                exception = e;
            }

            //then
            if (expectedError == null)
            {
                Assert.Null(exception);
            }
            else
            {
                Assert.That(exception.Message, Is.EqualTo(expectedError));
            }
        }

		static object[] UniqueHeaders =
		{
            new object[] { "example.com:extra_recipient_header" },
            new object[] { "alg" },
            new object[] { "enc" }
		};

        /// <summary>
        /// Enforce uniquness of header names - as per https://tools.ietf.org/html/rfc7516#section-4
        /// Here passed into extraHeaders
        /// </summary>
		[Test, TestCaseSource("UniqueHeaders")]			
        public void Encrypt_WithNonUniqueHeaderParameterNamesInExtraHeaders_Throws(string injectedHeaderName)
        {
            //given
            byte[] plaintext = { };

            //when
            var exception = Assert.Throws<ArgumentException>(delegate
            {
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
                        })
                    },
                    JweEncryption.A128CBC_HS256,
                    extraProtectedHeaders: new Dictionary<string, object>
                    {
                    { "cty", "text/plain" },
                    { "example.com:extra_header", "another value" },
                    { injectedHeaderName, string.Empty },
                });
            });

            //then
            Assert.NotNull(exception);            
            Assert.That(exception.Message, Is.StringContaining("An item with the same key has already been added."));
        }

        /// <summary>
        /// Enforce uniquness of header names - as per https://tools.ietf.org/html/rfc7516#section-4
        /// Here passed into recipient's headers
        /// </summary>
		[Test, TestCaseSource(nameof(UniqueHeaders))]
        public void Encrypt_WithNonUniqueHeaderParameterNamesInRecipientHeaders_Throws(string injectedHeaderName)
        {
            //given
            byte[] plaintext = { };

            //when
            var exception = Assert.Throws<ArgumentException>(delegate 
            {
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
                JweEncryption.A128CBC_HS256,
                extraProtectedHeaders: new Dictionary<string, object>
                {
                    { "cty", "text/plain" },
                    { "example.com:extra_header", "another value" },
                });
            });

            //then
            Assert.NotNull(exception);
            Assert.That(exception.Message, Is.StringContaining("An item with the same key has already been added."));
        }

        [Test]
        public void UnsafeJoseHeaders_ModeCompactWithEmptyBytesA128KW_A128CBC_HS256_ExpectedResults()
        {
            //given
            byte[] plaintext = { };
            var jwe = JWE.EncryptBytes(
                plaintext: plaintext,
                recipients: new JweRecipient[] { recipientAes128KW },
                JweEncryption.A128CBC_HS256,
                mode: SerializationMode.Compact);

            //when
            var test = JWE.Headers(jwe);

            //then
            Assert.That(test.Recipients.Count, Is.EqualTo(1));

            Assert.That(test.Recipients[0].JoseHeader.Count(), Is.EqualTo(2));
            Assert.That(test.Recipients[0].JoseHeader["enc"], Is.EqualTo("A128CBC-HS256"));
            Assert.That(test.Recipients[0].JoseHeader["alg"], Is.EqualTo("A128KW"));
        }

        [Test]
        public void UnsafeJoseHeaders_Rfc7516AppendixA23_ExpectedResults()
        {
            //when
            var test = JWE.Headers(Rfc7516_A_4_7_ExampleJwe);

            //then
            Assert.That(test.Recipients.Count(), Is.EqualTo(2));

            Assert.That(test.Recipients[0].JoseHeader.Count(), Is.EqualTo(4));
            Assert.That(test.Recipients[0].JoseHeader["enc"], Is.EqualTo("A128CBC-HS256"));
            Assert.That(test.Recipients[0].JoseHeader["jku"], Is.EqualTo("https://server.example.com/keys.jwks"));
            Assert.That(test.Recipients[0].JoseHeader["alg"], Is.EqualTo("RSA1_5"));
            Assert.That(test.Recipients[0].JoseHeader["kid"], Is.EqualTo("2011-04-29"));

            Assert.That(test.Recipients[1].JoseHeader.Count(), Is.EqualTo(4));
            Assert.That(test.Recipients[1].JoseHeader["enc"], Is.EqualTo("A128CBC-HS256"));
            Assert.That(test.Recipients[1].JoseHeader["jku"], Is.EqualTo("https://server.example.com/keys.jwks"));
            Assert.That(test.Recipients[1].JoseHeader["alg"], Is.EqualTo("A128KW"));
            Assert.That(test.Recipients[1].JoseHeader["kid"], Is.EqualTo("7"));
        }

        [Test]
        public void DecodeSingleRecipientProtectedHeader()
        {
            var token = @"{""ciphertext"":""tzh1xXdNDke99sLmZEnmYw"",""encrypted_key"":""DNszn45AFTiUAWsPeLi-AZd4oSkUKLK95FrRMpDv9qEe9TIA6QOPezOh7NrOzTXa8AdrbnDRQJwO7S_0i4p5xQrEukjkzelD"",""header"":{""alg"":""A256KW"",""enc"":""A256CBC-HS512""},""iv"":""480QxkaQPCiaEmxJFPxgsg"",""tag"":""dHeG5UCb4nCSbysUKva_4I_Z4D2WfYUaeasxOsJXTYg""}";

            var payload = Jose.JWE.Decrypt(token, sharedKey);

            Assert.That(payload.Plaintext, Is.EqualTo("Hello World"));

            Assert.That(2, Is.EqualTo(payload.Recipient.JoseHeader.Count));
            Assert.That("A256CBC-HS512", Is.EqualTo(payload.Recipient.JoseHeader["enc"]));
            Assert.That("A256KW", Is.EqualTo(payload.Recipient.JoseHeader["alg"]));
        }

        [Test]
        public void DecodeAAD()
        {
            var token = @"{""aad"":""ZXlKaGJHY2lPaUpCTVRJNFMxY2lMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySW4w"",""ciphertext"":""02VvoX1sUsmFi2ZpIbTI8g"",""encrypted_key"":""kH4te-O3DNZoDlxeDnBXM9CNx2d5IgVGO-cVMmqTRW_ws0EG_RKDQ7FLLztMM83z2s-pSNSZtFf3bx9Aky8XOzhIYCIU7XvmiQ0pp5z1FRdrwO-RxEOJfb2hAjD-hE5lCJkkY722QGs4IrUQ5N5Atc9h9-0vDcg-gksFIuaLMeRQj3LxivhwJO-QWFd6sG0FY6fBCwS1X6zsrZo-m9DNvrB6FhMpkLPBDOlCNnjKf1_Mz_jAuXIwnVUhoq59m8tvxQY1Fyngiug6zSnM207-0BTXzuCTnPgPAwGWGDLO7o0ttPT6RI_tLvYE6AuOynsqsHDaecyIkJ26dif3iRmkeg"",""header"":{""alg"":""RSA-OAEP-256"",""kid"":""Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc""},""iv"":""E1BAiqIeAH_0eInT59zb8w"",""protected"":""eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwidHlwIjoiSldFIn0"",""tag"":""yYBiajF5oMtyK3mRVQyPnlJL25hXW8Ct8ZMcFK5ehDY""}";

            var payload = Jose.JWE.Decrypt(token, PrivKey());

            Assert.That(payload.Plaintext, Is.EqualTo("Hello World"));

            Assert.That(4, Is.EqualTo(payload.Recipient.JoseHeader.Count));
            Assert.That("A256CBC-HS512", Is.EqualTo(payload.Recipient.JoseHeader["enc"]));
            Assert.That("RSA-OAEP-256", Is.EqualTo(payload.Recipient.JoseHeader["alg"]));
            Assert.That("Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc", Is.EqualTo(payload.Recipient.JoseHeader["kid"]));
            Assert.That("JWE", Is.EqualTo(payload.Recipient.JoseHeader["typ"]));
        }

        [Test]
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

            Assert.That(firstRecipient.Plaintext, Is.EqualTo("Hello World"));

            Assert.That(2, Is.EqualTo(firstRecipient.Recipient.JoseHeader.Count));
            Assert.That("A256GCM", Is.EqualTo(firstRecipient.Recipient.JoseHeader["enc"]));
            Assert.That("A256KW", Is.EqualTo(firstRecipient.Recipient.JoseHeader["alg"]));

            var secondRecipient = Jose.JWE.Decrypt(token, PrivKey());

            Assert.That(secondRecipient.Plaintext, Is.EqualTo("Hello World"));

            Assert.That(3, Is.EqualTo(secondRecipient.Recipient.JoseHeader.Count));
            Assert.That("A256GCM", Is.EqualTo(secondRecipient.Recipient.JoseHeader["enc"]));
            Assert.That("JWE", Is.EqualTo(secondRecipient.Recipient.JoseHeader["typ"]));
            Assert.That("RSA-OAEP-256", Is.EqualTo(secondRecipient.Recipient.JoseHeader["alg"]));
        }

        [Test]
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

            Assert.That(firstRecipient.Plaintext, Is.EqualTo("Hello World"));

            Assert.That(3, Is.EqualTo(firstRecipient.Recipient.JoseHeader.Count));
            Assert.That("A256CBC-HS512", Is.EqualTo(firstRecipient.Recipient.JoseHeader["enc"]));
            Assert.That("JWE", Is.EqualTo(firstRecipient.Recipient.JoseHeader["typ"]));
            Assert.That("A256KW", Is.EqualTo(firstRecipient.Recipient.JoseHeader["alg"]));

            var secondRecipient = Jose.JWE.Decrypt(token, PrivKey());

            Assert.That(secondRecipient.Plaintext, Is.EqualTo("Hello World"));

            Assert.That(4, Is.EqualTo(secondRecipient.Recipient.JoseHeader.Count));
            Assert.That("A256CBC-HS512", Is.EqualTo(secondRecipient.Recipient.JoseHeader["enc"]));
            Assert.That("JWE", Is.EqualTo(secondRecipient.Recipient.JoseHeader["typ"]));
            Assert.That("RSA-OAEP-256", Is.EqualTo(secondRecipient.Recipient.JoseHeader["alg"]));
            Assert.That("Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc", Is.EqualTo(secondRecipient.Recipient.JoseHeader["kid"]));
        }

        [Test]
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

            Assert.That(firstRecipient.Plaintext, Is.EqualTo("Hello World"));

            Assert.That(5, Is.EqualTo(firstRecipient.Recipient.JoseHeader.Count));
            Assert.That("A256CBC-HS512", Is.EqualTo(firstRecipient.Recipient.JoseHeader["enc"]));
            Assert.That("JWE", Is.EqualTo(firstRecipient.Recipient.JoseHeader["typ"]));
            Assert.That("PBES2-HS256+A128KW", Is.EqualTo(firstRecipient.Recipient.JoseHeader["alg"]));
            Assert.That(8192, Is.EqualTo(firstRecipient.Recipient.JoseHeader["p2c"]));
            Assert.That("kpL8s71MjhPnBExCF-cIMA", Is.EqualTo(firstRecipient.Recipient.JoseHeader["p2s"]));

            var secondRecipient = Jose.JWE.Decrypt(token, Ecc256Private());

            Assert.That(secondRecipient.Plaintext, Is.EqualTo("Hello World"));

            Assert.That(4, Is.EqualTo(secondRecipient.Recipient.JoseHeader.Count));
            Assert.That("A256CBC-HS512", Is.EqualTo(secondRecipient.Recipient.JoseHeader["enc"]));
            Assert.That("JWE", Is.EqualTo(secondRecipient.Recipient.JoseHeader["typ"]));
            Assert.That("ECDH-ES+A128KW", Is.EqualTo(secondRecipient.Recipient.JoseHeader["alg"]));
            Assert.True(secondRecipient.Recipient.JoseHeader.ContainsKey("epk"));

            var epk = (IDictionary<string, object>)secondRecipient.Recipient.JoseHeader["epk"];
            Assert.That(4, Is.EqualTo(epk.Count));
            Assert.That("P-256", Is.EqualTo(epk["crv"]));
            Assert.That("EC", Is.EqualTo(epk["kty"]));
            Assert.That("WOqJxZwzivLSO-r3qRkBVDd9uA_de_AIu3G3hkIQg1M", Is.EqualTo(epk["x"]));
            Assert.That("aFbCEl231v5IeA_Zjg8kMVJXxZWhpEHibtvHnq7Kk9k", Is.EqualTo(epk["y"]));
        }

        [Test]
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

        [Test]
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

        [Test]
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

        [Test]
        public void EncodeSingleRecipient()
        {
            var payload = "Hello World !";
            JweRecipient r = new JweRecipient(JweAlgorithm.A256KW, sharedKey);

            string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM);

            Console.Out.WriteLine("[JSON][A256KW][A256GCM]: {0}", token);

            JObject deserialized = JObject.Parse(token);

            Assert.That(UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])), Is.EqualTo("{\"enc\":\"A256GCM\"}"));

            Assert.True(deserialized["header"] is JObject);
            Assert.That(deserialized["header"].ToString(Newtonsoft.Json.Formatting.None), Is.EqualTo("{\"alg\":\"A256KW\"}"));
            Assert.That((string)deserialized["header"]["alg"], Is.EqualTo("A256KW"));
            Assert.That(((string)deserialized["encrypted_key"]).Length, Is.EqualTo(54)); //CEK size
            Assert.That(((string)deserialized["iv"]).Length, Is.EqualTo(16)); //IV size
            Assert.That(((string)deserialized["ciphertext"]).Length, Is.EqualTo(18)); //cipher text size
            Assert.That(((string)deserialized["tag"]).Length, Is.EqualTo(22)); //auth tag size

            var decoded = JWE.Decrypt(token, sharedKey);
            Assert.That(payload, Is.EqualTo(decoded.Plaintext));
        }

        [Test]
        public void EncodeWithAAD()
        {
            var payload = "Hello World !";
            JweRecipient r = new JweRecipient(JweAlgorithm.A256KW, sharedKey);

            var aad = new byte[] { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48 };

            string token = JWE.Encrypt(payload, new[] { r }, JweEncryption.A256GCM, aad);

            Console.Out.WriteLine("[JSON][A256KW][A256GCM][AAD]: {0}", token);

            JObject deserialized = JObject.Parse(token);

            Assert.That(UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])), Is.EqualTo("{\"enc\":\"A256GCM\"}"));

            Assert.True(deserialized["header"] is JObject);
            Assert.That(deserialized["header"].ToString(Newtonsoft.Json.Formatting.None), Is.EqualTo("{\"alg\":\"A256KW\"}"));
            Assert.That((string)deserialized["header"]["alg"], Is.EqualTo("A256KW"));
            Assert.That(((string)deserialized["encrypted_key"]).Length, Is.EqualTo(54)); //CEK size
            Assert.That(((string)deserialized["iv"]).Length, Is.EqualTo(16)); //IV size
            Assert.That(((string)deserialized["ciphertext"]).Length, Is.EqualTo(18)); //cipher text size
            Assert.That(((string)deserialized["tag"]).Length, Is.EqualTo(22)); //auth tag size


            var decoded = JWE.Decrypt(token, sharedKey);
            Assert.That(payload, Is.EqualTo(decoded.Plaintext));
        }

        [Test]
        public void EncodeMultipleRecipients()
        {
            var payload = "Hello World !";
            JweRecipient r1 = new JweRecipient(JweAlgorithm.PBES2_HS256_A128KW, "secret");
            JweRecipient r2 = new JweRecipient(JweAlgorithm.ECDH_ES_A128KW, Ecc256Public());
            JweRecipient r3 = new JweRecipient(JweAlgorithm.RSA_OAEP_256, PubKey());

            string token = JWE.Encrypt(payload, new[] { r1, r2, r3 }, JweEncryption.A256GCM, mode: SerializationMode.Json);

            Console.Out.WriteLine("[JSON][PBES2_HS256_A128KW, ECDH-ES+A128KW, RSA_OAEP_256][A256GCM]: {0}", token);

            JObject deserialized = JObject.Parse(token);

            Assert.That(UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])), Is.EqualTo("{\"enc\":\"A256GCM\"}"));


            Assert.That(((string)deserialized["iv"]).Length, Is.EqualTo(16)); //IV size
            Assert.That(((string)deserialized["ciphertext"]).Length, Is.EqualTo(18)); //cipher text size
            Assert.That(((string)deserialized["tag"]).Length, Is.EqualTo(22)); //auth tag size

            Assert.True(deserialized["recipients"] is JArray);
            Assert.That(((JArray)deserialized["recipients"]).Count, Is.EqualTo(3));
            var rec0 = ((JArray)deserialized["recipients"])[0];
            var rec1 = ((JArray)deserialized["recipients"])[1];
            var rec2 = ((JArray)deserialized["recipients"])[2];

            Assert.True(rec0["header"] is JObject);
            Assert.That((string)rec0["header"]["alg"], Is.EqualTo("PBES2-HS256+A128KW"));
            Assert.That((int)rec0["header"]["p2c"], Is.EqualTo(8192));
            Assert.That(((string)rec0["header"]["p2s"]).Length, Is.EqualTo(16));
            Assert.That(((string)rec0["encrypted_key"]).Length, Is.EqualTo(54));

            Assert.True(rec1["header"] is JObject);
            Assert.True(rec1["header"]["epk"] is JObject);
            Assert.That((string)rec1["header"]["alg"], Is.EqualTo("ECDH-ES+A128KW"));
            Assert.That((string)rec1["header"]["epk"]["kty"], Is.EqualTo("EC"));
            Assert.That((string)rec1["header"]["epk"]["crv"], Is.EqualTo("P-256"));
            Assert.That(((string)rec1["header"]["epk"]["x"]).Length, Is.EqualTo(43));
            Assert.That(((string)rec1["header"]["epk"]["y"]).Length, Is.EqualTo(43));
            Assert.That(((string)rec1["encrypted_key"]).Length, Is.EqualTo(54));

            Assert.True(rec2["header"] is JObject);
            Assert.That((string)rec2["header"]["alg"], Is.EqualTo("RSA-OAEP-256"));
            Assert.That(((string)rec2["encrypted_key"]).Length, Is.EqualTo(342));

            Assert.That(JWE.Decrypt(token, "secret").Plaintext, Is.EqualTo(payload));
            Assert.That(JWE.Decrypt(token, PrivKey()).Plaintext, Is.EqualTo(payload));
            Assert.That(JWE.Decrypt(token, Ecc256Private()).Plaintext, Is.EqualTo(payload));
        }

        [Test]
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

            Assert.That(UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])), Is.EqualTo("{\"enc\":\"A256GCM\"}"));

            Assert.True(deserialized["header"] is JObject);
            Assert.That(deserialized["header"].ToString(Newtonsoft.Json.Formatting.None), Is.EqualTo("{\"alg\":\"RSA-OAEP-256\"}"));

            Assert.True(deserialized["unprotected"] is JObject);
            Assert.That(deserialized["unprotected"].ToString(Newtonsoft.Json.Formatting.None), Is.EqualTo("{\"jku\":\"https://server.example.com/keys.jwks\"}"));

            Assert.That(((string)deserialized["iv"]).Length, Is.EqualTo(16)); //IV size
            Assert.That(((string)deserialized["ciphertext"]).Length, Is.EqualTo(18)); //cipher text size
            Assert.That(((string)deserialized["tag"]).Length, Is.EqualTo(22)); //auth tag size

            Assert.That(Encoding.UTF8.GetString(JWE.Decrypt(token, PrivKey()).PlaintextBytes), Is.EqualTo(payload));            
        }

        [Test]
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

            Assert.That(UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])), Is.EqualTo("{\"enc\":\"A256GCM\",\"jku\":\"https://server.example.com/keys.jwks\"}"));

            Assert.True(deserialized["header"] is JObject);
            Assert.That(deserialized["header"].ToString(Newtonsoft.Json.Formatting.None), Is.EqualTo("{\"alg\":\"RSA-OAEP-256\"}"));

            Assert.That(((string)deserialized["iv"]).Length, Is.EqualTo(16)); //IV size
            Assert.That(((string)deserialized["ciphertext"]).Length, Is.EqualTo(18)); //cipher text size
            Assert.That(((string)deserialized["tag"]).Length, Is.EqualTo(22)); //auth tag size

            Assert.That(Encoding.UTF8.GetString(JWE.Decrypt(token,PrivKey()).PlaintextBytes), Is.EqualTo(payload));
        }

        [Test]
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

            Assert.That(UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])), Is.EqualTo("{\"enc\":\"A256GCM\"}"));

            Assert.True(deserialized["header"] is JObject);
            Assert.That(deserialized["header"].ToString(Newtonsoft.Json.Formatting.None), Is.EqualTo("{\"alg\":\"RSA-OAEP-256\",\"kid\":\"2011-04-29\"}"));

            Assert.That(((string)deserialized["iv"]).Length, Is.EqualTo(16)); //IV size
            Assert.That(((string)deserialized["ciphertext"]).Length, Is.EqualTo(18)); //cipher text size
            Assert.That(((string)deserialized["tag"]).Length, Is.EqualTo(22)); //auth tag size

            Assert.That(Encoding.UTF8.GetString(JWE.Decrypt(token,PrivKey()).PlaintextBytes), Is.EqualTo(payload));
        }

        [Test]
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

        [Test]
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

        [Test]
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

        private static object GetLegacyKeyObjectFromJwk(string json)
        {
            var jwk=JsonConvert.DeserializeObject<IDictionary<string, string>>(json);
            switch (jwk["kty"])
            {
                case "RSA":
                    var rsa = RSA.Create();
                    rsa.ImportParameters(new RSAParameters()
                    {
                        Modulus = Base64Url.Decode(jwk["n"]),
                        Exponent = Base64Url.Decode(jwk["e"]),
                        D = Base64Url.Decode(jwk["d"]),
                        P = Base64Url.Decode(jwk["p"]),
                        Q = Base64Url.Decode(jwk["q"]),
                        DP = Base64Url.Decode(jwk["dp"]),
                        DQ = Base64Url.Decode(jwk["dq"]),
                        InverseQ = Base64Url.Decode(jwk["qi"]),
                    });
                    return rsa;

                case "oct":
                    return Base64Url.Decode(jwk["k"]);

                default:
                    throw new NotImplementedException($"Key type not implemented: {jwk["kty"]}");
            }
        }

        private static RSACryptoServiceProvider PrivKey()
        {
            var key = (RSACryptoServiceProvider)X509().PrivateKey;

            RSACryptoServiceProvider newKey = new RSACryptoServiceProvider();
            newKey.ImportParameters(key.ExportParameters(true));

            return newKey;
        }

        private static RSACryptoServiceProvider PubKey()
        {
            return (RSACryptoServiceProvider)X509().PublicKey.Key;
        }

        private static X509Certificate2 X509()
        {
            return new X509Certificate2("jwt-2048.p12", "1", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }

        private static CngKey Ecc256Public()
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EccKey.New(x, y, usage: CngKeyUsages.KeyAgreement);
        }

        private static CngKey Ecc256Private()
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EccKey.New(x, y, d, CngKeyUsages.KeyAgreement);
        }

        private static readonly byte[] sharedKey = new byte[] { 21, 26, 196, 88, 134, 11, 137, 127, 215, 118, 142, 180, 138, 115, 246, 247, 179, 182, 140, 136, 76, 33, 206, 189, 255, 22, 243, 100, 251, 74, 254, 161 };

        private static readonly byte[] aes256KWKey1 = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, };

        private static readonly byte[] aes256KWKey2 = new byte[] { 94, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, };

        private static readonly byte[] aes256KWKey3 = new byte[] { 4, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, };

        private static byte[] aes128KWKey = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };

        private static JweRecipient recipientEcdhEs1 = new JweRecipient(JweAlgorithm.ECDH_ES, Ecc256Public());

        private static JweRecipient recipientAes256KW1 = new JweRecipient(JweAlgorithm.A256KW, aes256KWKey1);

        private static JweRecipient recipientAes256KW2 = new JweRecipient(JweAlgorithm.A256KW, aes256KWKey2);

        private static JweRecipient recipientAes128KW = new JweRecipient(JweAlgorithm.A128KW, aes128KWKey);

        private static JweRecipient recipientDirectEncyption1 = new JweRecipient(JweAlgorithm.DIR, aes256KWKey1);

        private static JweRecipient recipientRsa1 = new JweRecipient(JweAlgorithm.RSA1_5, PubKey());

        private static string Rfc7516_A_4_7_ExampleJwe = @"
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


        private static string Rfc7516_A_2_3_ExampleJwk = @"
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

        private static string Rfc7516_A_3_3_ExampleJwk = @"
            {""kty"":""oct"",
            ""k"":""GawgguFyGrWKav7AX4VKUg""
            }";

        private static string Rfc7520_5_10_ExampleJwe = @"
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

        private static string Rfc7520_5_8_1_Figure151_ExampleJwk = @"
            {
             ""kty"": ""oct"",
             ""kid"": ""81b20965-8332-43d9-a468-82160ad91ac8"",
             ""use"": ""enc"",
             ""alg"": ""A128KW"",
             ""k"": ""GZy6sIZ6wl9NJOKB-jnmVQ""
            }";

        private static string Rfc7520_Figure72_ExamplePlaintext =
               "You can trust us to stick with you through thick and "
               + "thin\x2013to the bitter end. And you can trust us to "
               + "keep any secret of yours\x2013closer than you keep it "
               + "yourself. But you cannot trust us to let you face trouble "
               + "alone, and go off without a word. We are your friends, Frodo.";


        private static string Rfc7520_Figure176_ExampleBase64UrlEncodedAad =
            "WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxbImZuIix7fS"
               + "widGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4iLHt9LCJ0ZXh0Iixb"
               + "IkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIsIiJdXSxbImJkYXkiLHt9LC"
               + "J0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVyIix7fSwidGV4dCIsIk0iXV1d";

        private static string Rfc7520_5_10_1_ExampleAadString =
            "[\"vcard\",[[\"version\",{},\"text\",\"4.0\"],[\"fn\",{},\"text\",\"Meriadoc Brandybuck\"],[\"n\",{},\"text\",[\"Brandybuck\",\"Meriadoc\",\"Mr.\",\"\"]],[\"bday\",{},\"text\",\"TA 2982\"],[\"gender\",{},\"text\",\"M\"]]]";
    };
}