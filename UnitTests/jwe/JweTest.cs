namespace UnitTests.Jwe
{
    using Jose;
    using Jose.jwe;
    using Newtonsoft.Json.Linq;
    using System;
    using System.Collections.Generic;
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
                recipientAes256KW,
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

            var decrypted = Jwe.Decrypt(jwe, aes256KWKey, mode: mode);

            //then
            Assert.Equal(payload, decrypted.Plaintext);
        }

        public static IEnumerable<object[]> RecipientTestData =>
            new List<object[]>
            {
                new object[] { aes256KWKey, null },
                new object[] { aes128KWKey, null },
                new object[] { aes128KWKey2, "Could not decrypt JWE." },
            };
            
        [Theory(Skip = "TODO - multi recipient round trip not yet working")]
        [MemberData(nameof(RecipientTestData))]
        public void EncryptDecrypt_ModeGeneralJsonRoundTripMultipleRecipients_AllRecipientsCanDecrypt(object decryptKey, string expectedError)
        {
            //given
            byte[] payload = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            var recipients = new JweRecipient[]
            {
                recipientAes256KW,
                recipientAes128KW,
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
        [InlineData(SerializationMode.smCompact, "Only one recipient is supported by the JWE Compact Serialization.")]
        [InlineData(SerializationMode.smFlattenedJson, "Only one recipient is supported by the Flattened JWE JSON Serialization.")]
        [InlineData(SerializationMode.smGeneralJson, "Multi-recipient encrypt still in-progress")]
        public void Encrypt_WithMoreThanOneRecipient_Throws(SerializationMode mode, string expectedMessage)
        {
            //given
            byte[] plaintext = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            var recipients = new JweRecipient[]
            {
                recipientAes256KW,
                recipientAes128KW,
            };

            //when
            Func<string> act = () => Jwe.Encrypt(
                plaintext: plaintext,
                recipients: recipients,
                JweEncryption.A256GCM,
                mode: mode);

            //then
            var exception = Assert.Throws<JoseException>(act);
            Assert.Equal(expectedMessage, exception.Message);
        }

        [Fact]
        public void Encrypt_ModeCompactWithEmptyBytesA128KW_A128CBC_HS256_ExpectedResults()
        {
            //when
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
            //when
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
            //when
            byte[] plaintext = { };

            //when
            var jwe = Jwe.Encrypt(
                plaintext: plaintext,
                recipients: new JweRecipient[] { recipientAes128KW },
                JweEncryption.A128CBC_HS256,
                mode: SerializationMode.smFlattenedJson);

            //then
            Console.Out.WriteLine("Empty bytes A128KW_A128CBC_HS256 (Flattened Json Serialization) = {0}", jwe);

            //dynamic deserialized = JsonConvert.DeserializeObject(jwe);
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

        [Fact(Skip = "TODO - see https://tools.ietf.org/html/rfc7516#section-4")]
        void Encrypt_WithNonUniqueHeaderParameterNames_Throws()
        {

        }

        [Fact(Skip = "TODO - see https://tools.ietf.org/html/rfc7516#section-4")]
        void Decrypt_WithNonUniqueHeaderParameterNames_Throws()
        {

        }
        
        private static readonly byte[] aes256KWKey = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133, };

        private static byte[] aes128KWKey = new byte[] { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };

        private static byte[] aes128KWKey2 = new byte[] { 94, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };

        private static JweRecipient recipientAes256KW => new JweRecipient(JweAlgorithm.A256KW, aes256KWKey);

        private static JweRecipient recipientAes128KW => new JweRecipient(JweAlgorithm.A128KW, aes128KWKey);
    };
}
