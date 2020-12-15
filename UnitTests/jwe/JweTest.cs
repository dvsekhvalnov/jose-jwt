namespace UnitTests.Jwe
{
    using Jose;
    using Jose.jwe;
    using Jose.keys;
    using Microsoft.IdentityModel.Tokens;
    using Newtonsoft.Json.Linq;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using Xunit;

    public class JweTest
    {
        [Theory]
        [InlineData(SerializationMode.smCompact)]
        [InlineData(SerializationMode.smGeneralJson)]
        [InlineData(SerializationMode.smFlattenedJson)]
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
            var jwe = Jwe.Encrypt(
                plaintext: payload,
                recipients: recipients,
                JweEncryption.A256GCM,
                mode: mode,
                extraHeaders: sharedProtectedHeaders);

            var decrypted = Jwe.Decrypt(jwe, aes256KWKey1, mode: mode);

            //then
            Assert.Equal(payload, decrypted.Plaintext);
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
            var jwe = Jwe.Encrypt(
                plaintext: payload,
                recipients: recipients,
                JweEncryption.A256GCM,
                mode: SerializationMode.smGeneralJson,
                extraHeaders: sharedProtectedHeaders);

            var decrypted = Jwe.Decrypt(jwe, decryptKey, mode: SerializationMode.smGeneralJson);

            //then
            Assert.Equal(payload, decrypted.Plaintext);
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
            var jwe = Jwe.Encrypt(
                plaintext: payload,
                recipients: recipients,
                JweEncryption.A256GCM,
                mode: SerializationMode.smGeneralJson,
                extraHeaders: sharedProtectedHeaders);


            //when
            var exception = Record.Exception(() => Jwe.Decrypt(jwe, aes256KWKey2, expectedJweAlg, expectedJweEnc, mode: SerializationMode.smGeneralJson));

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
            var jwe = Jwe.Encrypt(
                plaintext: payload,
                recipients: recipients,
                JweEncryption.A256GCM,
                mode: SerializationMode.smGeneralJson,
                extraHeaders: sharedProtectedHeaders);

            //when
            var exception = Record.Exception(() => { Jwe.Decrypt(jwe, aes256KWKey3, mode: SerializationMode.smGeneralJson); });

            //then
            Assert.IsType<IntegrityException>(exception);
            Assert.Equal("AesKeyWrap integrity check failed.", exception.Message);            
        }

        [Theory]
        [InlineData(SerializationMode.smCompact, "Only one recipient is supported by the JWE Compact Serialization.")]
        [InlineData(SerializationMode.smFlattenedJson, "Only one recipient is supported by the Flattened JWE JSON Serialization.")]
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
            var exception = Record.Exception(() => Jwe.Encrypt(
                plaintext: plaintext,
                recipients: recipients,
                JweEncryption.A256GCM,
                mode: mode));

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
            var jwe = Jwe.Encrypt(
                plaintext: plaintext,
                recipients: new JweRecipient[] { recipientAes128KW },
                JweEncryption.A128CBC_HS256);

            //then
            Console.Out.WriteLine("Empty bytes A128KW_A128CBC_HS256 = {0}", jwe);

            string[] parts = jwe.Split('.');

            Assert.Equal(5, parts.Length); //Make sure 5 parts
            // Note the order of enc and alg is swapped compared to TestSuite.EncryptEmptyBytes_A128KW_A128CBC_HS256
            // however the order of keys in a json dictionary doesn't matter and not actually defined for C# dictionary
            Assert.Equal("{\"enc\":\"A128CBC-HS256\",\"alg\":\"A128KW\"}",
                UTF8Encoding.UTF8.GetString(Base64Url.Decode(parts[0]))); //Header is non-encrypted and static text            
            Assert.Equal(54, parts[1].Length); //CEK size
            Assert.Equal(22, parts[2].Length); //IV size
            Assert.Equal(22, parts[3].Length); //cipher text size
            Assert.Equal(22, parts[4].Length); //auth tag size

            Assert.Equal(new byte[0], Jwe.Decrypt(jwe, aes128KWKey).Plaintext);
        }

        [Fact]
        public void Encrypt_ModeGeneralJsonWithEmptyBytesA128KW_A128CBC_HS256_ExpectedResults()
        {
            //given
            byte[] plaintext = { };

            //when
            var jwe = Jwe.Encrypt(
                plaintext: plaintext,
                recipients: new JweRecipient[] { recipientAes128KW },
                JweEncryption.A128CBC_HS256,
                mode: SerializationMode.smGeneralJson);

            //then
            Console.Out.WriteLine("Empty bytes A128KW_A128CBC_HS256 (General Json Serialization) = {0}", jwe);

            //dynamic deserialized = JsonConvert.DeserializeObject(jwe);
            JObject deserialized = JObject.Parse(jwe);

            Assert.Equal("{\"enc\":\"A128CBC-HS256\"}",
                 UTF8Encoding.UTF8.GetString(Base64Url.Decode((string)deserialized["protected"])));

            Assert.True(deserialized["recipients"] is JArray);
            Assert.Single(((JArray)deserialized["recipients"]));

            var recipient0 = ((JArray)deserialized["recipients"])[0];

            Assert.True(recipient0["header"] is JObject); 
            Assert.Equal("{\"alg\":\"A128KW\"}", recipient0["header"].ToString(Newtonsoft.Json.Formatting.None));
            Assert.Equal("A128KW", recipient0["header"]["alg"]);
            Assert.Equal(54, ((string)recipient0["encrypted_key"]).Length); //CEK size
            Assert.Equal(22, ((string)deserialized["iv"]).Length); //IV size
            Assert.Equal(22, ((string)deserialized["ciphertext"]).Length); //cipher text size
            Assert.Equal(22, ((string)deserialized["tag"]).Length); //auth tag size

            Assert.Equal(new byte[0], Jwe.Decrypt(jwe, aes128KWKey, mode: SerializationMode.smGeneralJson).Plaintext);
        }

        [Fact]
        public void Encrypt_ModeFlattenedJsonWithEmptyBytesA128KW_A128CBC_HS256_ExpectedResults()
        {
            //given
            byte[] plaintext = { };

            //when
            var jwe = Jwe.Encrypt(
                plaintext: plaintext,
                recipients: new JweRecipient[] { recipientAes128KW },
                JweEncryption.A128CBC_HS256,
                mode: SerializationMode.smFlattenedJson);

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

            Assert.Equal(new byte[0], Jwe.Decrypt(jwe, aes128KWKey, mode: SerializationMode.smFlattenedJson).Plaintext);
        }

        [Fact]
        public void Decrypt_Rfc7516AppendixA23DecryptWithFirstRecipient_ExpectedResults()
        {
            //given
            var key = GetKeyFromJwk(Rfc7516_A_2_3_ExampleJwk);

            //when
            var decrypted = Jwe.Decrypt(
                Rfc7516_A_4_7_ExampleJwe,
                key,
                mode: SerializationMode.smGeneralJson);

            //then
            Assert.Equal("Live long and prosper.", UTF8Encoding.UTF8.GetString(decrypted.Plaintext));

            Assert.Equal(4, decrypted.JoseHeaders.Count);

            Assert.Equal("RSA1_5", decrypted.JoseHeaders["alg"]);
            Assert.Equal("2011-04-29", decrypted.JoseHeaders["kid"]);
            Assert.Equal("A128CBC-HS256", decrypted.JoseHeaders["enc"]);
            Assert.Equal("https://server.example.com/keys.jwks", decrypted.JoseHeaders["jku"]);
        }

        [Fact]
        public void Decrypt_Rfc7516AppendixA23DecryptWithSecondRecipient_ExpectedResults()
        {
            //given
            var key = GetKeyFromJwk(Rfc7516_A_3_3_ExampleJwk);

            //when
            var decrypted = Jwe.Decrypt(
                Rfc7516_A_4_7_ExampleJwe,
                key,
                mode: SerializationMode.smGeneralJson);

            //then
            Assert.Equal("Live long and prosper.", UTF8Encoding.UTF8.GetString(decrypted.Plaintext));

            Assert.Equal(4, decrypted.JoseHeaders.Count);

            Assert.Equal("A128KW", decrypted.JoseHeaders["alg"]);
            Assert.Equal("7", decrypted.JoseHeaders["kid"]);
            Assert.Equal("A128CBC-HS256", decrypted.JoseHeaders["enc"]);
            Assert.Equal("https://server.example.com/keys.jwks", decrypted.JoseHeaders["jku"]);
        }

        public static IEnumerable<object[]> TestDataMultipleRecipientDirectEncryption =>
            new List<object[]>
            {
                new object[] { new JweRecipient[] { recipientDirectEncyption1 }, null }, // (Single direct encryption is ok)
                new object[] { new JweRecipient[] { recipientDirectEncyption1, recipientAes256KW1 }, null }, // (Direct recipient currently allowed as first receipient)
                new object[] { new JweRecipient[] { recipientAes256KW1, recipientDirectEncyption1 }, "Direct Encryption not supported for multi-recipient JWE.", }, // (Direct recipient in multi not supported)                
                new object[] { new JweRecipient[] { recipientEcdhEs1, recipientAes256KW1 }, null, }, // (EcdhEs is ok as first recipient of a multi)"
                new object[] { new JweRecipient[] { recipientAes256KW1, recipientEcdhEs1 }, "(Direct) ECDH-ES key management cannot use existing CEK.", }, // (EcdhEs can not re-use a cek, e.g not be 2nd or later recipient)
            };

        [Theory()]
        [MemberData(nameof(TestDataMultipleRecipientDirectEncryption))]
        public void Encrypt_MultipleRecipient_SpecialCasesHandled(JweRecipient[] recipients, string expectedError)
        {
            //given
            byte[] plaintext = { };

            //when
            var exception = Record.Exception(() => Jwe.Encrypt(
                plaintext: plaintext,
                recipients: recipients,
                JweEncryption.A128CBC_HS256,
                mode: SerializationMode.smGeneralJson));

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
            var exception = Record.Exception(() => Jwe.Encrypt(
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
                mode: SerializationMode.smFlattenedJson,
                extraHeaders: new Dictionary<string, object>
                {
                    { "cty", "text/plain" },
                    { "example.com:extra_header", "another value" },
                    { injectedHeaderName, string.Empty },
                }));

            //then
            Assert.NotNull(exception);
            Assert.IsType<ArgumentException>(exception);
            Assert.Equal($"An item with the same key has already been added. Key: {injectedHeaderName}", exception.Message);
        }

        /// <summary>
        /// Enforce uniquness of header names - as per https://tools.ietf.org/html/rfc7516#section-4
        /// Here passed into recipient's headers
        /// </summary>
        [Theory]
        [InlineData("example.com:extra_header")]
        [InlineData("alg")]
        [InlineData("enc")]
        void Encrypt_WithNonUniqueHeaderParameterNamesInRecipientHeaders_Throws(string injectedHeaderName)
        {
            //given
            byte[] plaintext = { };

            //when
            var exception = Record.Exception(() => Jwe.Encrypt(
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
                mode: SerializationMode.smFlattenedJson,
                extraHeaders: new Dictionary<string, object>
                {
                    { "cty", "text/plain" },
                    { "example.com:extra_header", "another value" },                    
                }));

            //then
            Assert.NotNull(exception);
            Assert.IsType<ArgumentException>(exception);
            Assert.Equal($"An item with the same key has already been added. Key: {injectedHeaderName}", exception.Message);
        }

        private static object GetKeyFromJwk(string serializedJwk)
        {
            var jwk = new JsonWebKey(serializedJwk);
            switch (jwk.Kty)
            {
                case "RSA":
                    return RSA.Create(new RSAParameters()
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
            return new X509Certificate2("jwt-2048.p12", "1");
        }

        private static CngKey Ecc256Public(CngKeyUsages usage = CngKeyUsages.Signing)
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EccKey.New(x, y, usage: usage);
        }

        private static readonly byte[] aes256KWKey1 = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, };

        private static readonly byte[] aes256KWKey2 = new byte[] { 94, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, };

        private static readonly byte[] aes256KWKey3 = new byte[] { 4, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, };

        private static byte[] aes128KWKey = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };

        private static JweRecipient recipientEcdhEs1 => new JweRecipient(JweAlgorithm.ECDH_ES, Ecc256Public(CngKeyUsages.KeyAgreement));

        private static JweRecipient recipientAes256KW1 => new JweRecipient(JweAlgorithm.A256KW, aes256KWKey1);

        private static JweRecipient recipientAes256KW2 => new JweRecipient(JweAlgorithm.A256KW, aes256KWKey2);

        private static JweRecipient recipientAes128KW => new JweRecipient(JweAlgorithm.A128KW, aes128KWKey);

        private static JweRecipient recipientDirectEncyption1 => new JweRecipient(JweAlgorithm.DIR, aes256KWKey1);

        private static JweRecipient recipientRsa1 => new JweRecipient(JweAlgorithm.RSA1_5, PubKey());

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
    };
}