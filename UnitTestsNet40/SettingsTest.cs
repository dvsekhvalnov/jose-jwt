using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Jose;
using Jose.jwe;
using NUnit.Framework;

namespace UnitTests
{
    [TestFixture]
    public class SettingsTest
    {
        private byte[] aes128Key = { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };

        [Test]
        public void Encode_IJsonMapper_Override()
        {
            //given            
            MockJsonMapper jsMapper = new MockJsonMapper();

            var payload = new
            {
                hello = "world"
            };
            //when
            string token = Jose.JWT.Encode(payload, null, JwsAlgorithm.none, 
                settings: new JwtSettings().RegisterMapper(jsMapper));

            Console.Out.WriteLine("Plaintext:" + token);

            //then
            Assert.That(token, Is.EqualTo("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJoZWxsbyI6IndvcmxkIn0."));
            Assert.True(jsMapper.SerializeCalled);
        }

        [Test]
        public void Decode_IJsonMapper_Override()
        {
            //given
            JwtSettings settings = new JwtSettings();
            MockJsonMapper jsMapper = new MockJsonMapper();
            settings.JsonMapper = jsMapper;
            string token = "eyJhbGciOiJub25lIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.";

            //when
            var test = Jose.JWT.Decode<IDictionary<string, object>>(token, settings: settings);

            //then
            Assert.That(test, Is.EqualTo(new Dictionary<string, object> { { "hello", "world" } }));
            Assert.True(jsMapper.ParseCalled);
        }

        [Test]
        public void Encode_IJwsAlgorithm_Override()
        {
            //given            
            MockJwsAlgorithm jwsAlg = new MockJwsAlgorithm();

            var payload = new
            {
                hello = "world"
            };

            //when
            string token = Jose.JWT.Encode(payload, null, 
                JwsAlgorithm.none,  settings: new JwtSettings().RegisterJws(JwsAlgorithm.none, jwsAlg));

            Console.Out.WriteLine("Plaintext:" + token);

            //then
            Assert.That(token, Is.EqualTo("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJoZWxsbyI6IndvcmxkIn0."));
            Assert.True(jwsAlg.SignCalled);
        }

        [Test]
        public void Decode_IJwsAlgorithm_Override()
        {
            //given
            MockJwsAlgorithm jwsAlg = new MockJwsAlgorithm();

            string token = "eyJhbGciOiJub25lIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.";

            //when
            var test = Jose.JWT.Decode<IDictionary<string, object>>(token, settings: new JwtSettings().RegisterJws(JwsAlgorithm.none, jwsAlg));

            //then
            Assert.That(test, Is.EqualTo(new Dictionary<string, object> { { "hello", "world" } }));
            Assert.True(jwsAlg.VerifyCalled);
        }

        [Test]
        public void Encode_IJweAlgorithm_Override()
        {
            //given
            MockJweAlgorithm encAlg = new MockJweAlgorithm(128);
            
            string json =
                @"{""exp"":1389189552,""sub"":""alice"",""nbf"":1389188952,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""e543edf6-edf0-4348-8940-c4e28614d463"",""iat"":1389188952}";

            //when
            string token = Jose.JWT.Encode(json, aes128Key, JweAlgorithm.DIR, JweEncryption.A128GCM, settings: new JwtSettings().RegisterJwe(JweEncryption.A128GCM, encAlg));

            //then
            Console.Out.WriteLine("DIR_A128GCM = {0}", token);

            Assert.That(Jose.JWT.Decode(token, aes128Key), Is.EqualTo(json));
            Assert.True(encAlg.EncryptCalled);
        }

        [Test]
        public void Decode_IJweAlgorithm_Override()
        {
            //given            
            MockJweAlgorithm encAlg = new MockJweAlgorithm(128);

            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..yVi-LdQQngN0C5WS.1McwSmhZzAtmmLp9y-OdnJwaJFo1nj_4ashmzl2LhubGf0Jl1OTEVJzsHZb7bkup7cGTkuxh6Vfv10ljHsjWf_URXoxP3stQqQeViVcuPV0y2Q_WHYzTNGZpmHGe-hM6gjDhyZyvu3yeXGFSvfPQmp9pWVOgDjI4RC0MQ83rzzn-rRdnZkznWjbmOPxwPrR72Qng0BISsEwbkPn4oO8-vlHkVmPpuDTaYzCT2ZR5K9JnIU8d8QdxEAGb7-s8GEJ1yqtd_w._umbK59DAKA3O89h15VoKQ";

            //when
            string json = Jose.JWT.Decode(token, aes128Key, settings: new JwtSettings().RegisterJwe(JweEncryption.A128GCM, encAlg));

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1392548520,""sub"":""alice"",""nbf"":1392547920,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""0e659a67-1cd3-438b-8888-217e72951ec9"",""iat"":1392547920}"));
            Assert.True(encAlg.DecryptCalled);
        }

        [Test]
        public void Encode_IKeyManagement_Override()
        {
            //given            
            MockKeyManagement keyMgmt = new MockKeyManagement();
            string json =
                @"{""exp"":1389189552,""sub"":""alice"",""nbf"":1389188952,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""e543edf6-edf0-4348-8940-c4e28614d463"",""iat"":1389188952}";

            //when
            string token = Jose.JWT.Encode(json, aes128Key, JweAlgorithm.DIR, JweEncryption.A128GCM, settings: new JwtSettings().RegisterJwa(JweAlgorithm.DIR, keyMgmt));

            //then
            Console.Out.WriteLine("DIR_A128GCM = {0}", token);

            string[] parts = token.Split('.');          

            Assert.That(Jose.JWT.Decode(token, aes128Key), Is.EqualTo(json));

            Assert.True(keyMgmt.WrapCalled);
        }

        [Test]
        public void Decode_IKeyManagement_Override()
        {
            //given            
            MockKeyManagement keyMgmt = new MockKeyManagement();
            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..yVi-LdQQngN0C5WS.1McwSmhZzAtmmLp9y-OdnJwaJFo1nj_4ashmzl2LhubGf0Jl1OTEVJzsHZb7bkup7cGTkuxh6Vfv10ljHsjWf_URXoxP3stQqQeViVcuPV0y2Q_WHYzTNGZpmHGe-hM6gjDhyZyvu3yeXGFSvfPQmp9pWVOgDjI4RC0MQ83rzzn-rRdnZkznWjbmOPxwPrR72Qng0BISsEwbkPn4oO8-vlHkVmPpuDTaYzCT2ZR5K9JnIU8d8QdxEAGb7-s8GEJ1yqtd_w._umbK59DAKA3O89h15VoKQ";

            //when
            string json = Jose.JWT.Decode(token, aes128Key, settings: new JwtSettings().RegisterJwa(JweAlgorithm.DIR, keyMgmt));

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1392548520,""sub"":""alice"",""nbf"":1392547920,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""0e659a67-1cd3-438b-8888-217e72951ec9"",""iat"":1392547920}"));
            Assert.True(keyMgmt.UnwrapCalled);
        }

        [Test]
        public void Encode_ICompression_Override()
        {
            //given            
            MockCompression compress = new MockCompression();
            JwtSettings settings = new JwtSettings().RegisterCompression(JweCompression.DEF, compress);

            string json =
                @"{""exp"":1389189552,""sub"":""alice"",""nbf"":1389188952,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""e543edf6-edf0-4348-8940-c4e28614d463"",""iat"":1389188952}";

            //when
            string token = Jose.JWT.Encode(json, PubKey(), JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM, JweCompression.DEF, settings: settings);

            //then
            Console.Out.WriteLine("RSA-OAEP_A256GCM-DEFLATE = {0}", token);

            string[] parts = token.Split('.');

            Assert.That(Jose.JWT.Decode(token, PrivKey()), Is.EqualTo(json));

            Assert.True(compress.CompressCalled);
        }

        [Test]
        public void Decode_ICompression_Override()
        {
            //given           
            MockCompression compress = new MockCompression();

            string token = "eyJhbGciOiJSU0EtT0FFUCIsInppcCI6IkRFRiIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.nXSS9jDwE0dXkcGI7UquZBhn2nsB2P8u-YSWEuTAgEeuV54qNU4SlE76bToI1z4LUuABHmZOv9S24xkF45b7Mrap_Fu4JXH8euXrQgKQb9o_HL5FvE8m4zk5Ow13MKGPvHvWKOaNEBFriwYIfPi6QBYrpuqn0BaANc_aMyInV0Fn7e8EAgVmvoagmy7Hxic2sPUeLEIlRCDSGa82mpiGusjo7VMJxymkhnMdKufpGPh4wod7pvgb-jDWasUHpsUkHqSKZxlrDQxcy1-Pu1G37TAnImlWPa9NU7500IXc-W07IJccXhR3qhA5QaIyBbmHY0j1Dn3808oSFOYSF85A9w.uwbZhK-8iNzcjvKRb1a2Ig.jxj1GfH9Ndu1y0b7NRz_yfmjrvX2rXQczyK9ZJGWTWfeNPGR_PZdJmddiam15Qtz7R-pzIeyR4_qQoMzOISkq6fDEvEWVZdHnnTUHQzCoGX1dZoG9jXEwfAk2G1vXYT2vynEQZ72xk0V_OBtKhpIAUEFsXwCUeLAAgjFNY4OGWZl_Kmv9RTGhnePZfVbrbwg.WuV64jlV03OZm99qHMP9wQ";

            //when
            string json = Jose.JWT.Decode(token, PrivKey(), settings: new JwtSettings().RegisterCompression(JweCompression.DEF, compress));

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1392963710,""sub"":""alice"",""nbf"":1392963110,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""9fa7a38a-28fd-421c-825c-8fab3bbf3fb4"",""iat"":1392963110}"));
            Assert.True(compress.DecompressCalled);
        }

        [Test]
        public void Decode_JwsAlgorithm_Alias()
        {
            string token = "eyJhbGciOiJOT05FLUFMSUFTIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.";

            var test = Jose.JWT.Decode<IDictionary<string, object>>(token, settings: new JwtSettings().RegisterJwsAlias("NONE-ALIAS", JwsAlgorithm.none));

            Assert.That(test, Is.EqualTo(new Dictionary<string, object> { { "hello", "world" } }));
        }

        [Test]
        public void Decode_JweAlgorithm_Alias()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzVfQUxJQVMiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.dMCd2RbBtGBb9QwpJ0lYbJ0zv5Nagl5SPwRhrJTlXTDWJ6s-Ztz0-SEOi_gXx0SxXGA2iy5gY3x2uWbi-TSZvBuNyATYqoHlPLTCvNW47_INL8Gw46VcNu54urKadPh01Agk9WajBBlx9fnGgQMw5F9YNZbo8LfUNbGnZDYaxB3Vbyhn1Q9j3X8cT2MfzQ0uEhqr4FTx12oCd-6rZXXHhGnfdOKJGaihGLf10JVJcGXwBVY4AghEcAsii0JJrk35kLjBnzfsjlb2pB1r7k_tI6_1g06-5ubz_oEtlwGBM9OeqYnTk66A4a8vUSzqEC9e3bEQbWwz94Qv2qO5r9dy5Q.Axsj29AR41DivbI_MwHVtg.OMQpAiDkqJsZo53bSz9XmKwzqnLBqI7MR7mp0NazAqI.V_t4NP94yJyKAUmeTgrysQ";

            //when
            string json = Jose.JWT.Decode(token, PrivKey(), settings: new JwtSettings().RegisterJwaAlias("RSA1_5_ALIAS", JweAlgorithm.RSA1_5));

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""hello"":""world""}"));
        }

        [Test]
        public void Decode_JweEncryption_Alias()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2X0FMSUFTIn0.O1GahcMJNBaTEgPeOPzjm-FistaXkzmdZMPB0YkJoI6X1KIc43HJjLH28njXLQ-mGKblEhJwyFar4yfyrV9bzRSxe9K7RNDuG31m83D9yo-A2Mx1FZtvSUwm5yT62Xk0-BuZOq6S3algXvgTQie1MGRuSED-a6xmRj5RcEpop5JdEXnnlwCrn4qZt9jQpT_Ag_URgkNyuBJG878MXjArxU9Ci5WS1a-tcOgCtd33JOiCvniIBQBPFdyoz7vGZi3Y7EGhY-6T6dxyeL-_MMbkl_60HlTPrd6exfZ3c_0ofwSgvua_gAdSEN4inJWxJjH2yXiR0Ylj_lXAq_la3xFAhA.R2kyFSctYUZgIYJrUTWl8Q.LS4PGAa0bE-OyshBxUh5XhFvquKffEsSmEVU_LxSRAQ.hDDEkppjnfWUv_jKUcA6DQ";

            //when
            string json = Jose.JWT.Decode(token, PrivKey(), settings: new JwtSettings().RegisterJweAlias("A128CBC-HS256_ALIAS", JweEncryption.A128CBC_HS256));

            //then
            Console.Out.WriteLine("json = {0}", token);

            Assert.That(json, Is.EqualTo(@"{""hello"":""world""}"));
        }

        [Test]
        public void Decode_Compression_Alias()
        {
            string token = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiemlwIn0.PzQ3tGp6KqC_SBcFtHTJMdpPbGNlOJdIN-uFmwfaF6AU3Tb0mFHf4gcQnCMpB-_8HHUnllJPQJiMvbPS4z-tBgxuG8SlVmGA8dKGfYSrWh8kou1Mcs1WfL4PCNKna2bPr8sRSCIBzb5kWNjT-TuIHJA3_sL2MELdd8Mrny4Cua2i0UofMNvwsy7wpaCMZ03EI1_icZkzBmNUBSvv1W1vNBOfIRlXxDEgN6Zz9B-_Id4y8RK51wvXSb6kDQdC-pc8MCHZq-6GJ3S8CmTDVlBgbXyOOEH3Ke9EX4uJl1GTE6FtF2jJaWPy03HAJ615ZfRpe4hybl99XDPWzFhgBrYsOg.lYhsnbbRXx0ZSRK-A3Y1Iw.sw-VviW-zl-m7XBVVwOTDj5-YhSa-4NVLztAapzgDzk.VrZKYS2KKCgp4DaHijQx_w";

            var test = Jose.JWT.Decode<IDictionary<string, object>>(token, PrivKey(), settings: new JwtSettings().RegisterCompressionAlias("zip", JweCompression.DEF));

            Assert.That(test, Is.EqualTo(new Dictionary<string, object> { { "hello", "world" } }));
        }

        #region test utils

        private RSACryptoServiceProvider PrivKey()
        {
            var key = (RSACryptoServiceProvider)X509().PrivateKey;

            RSACryptoServiceProvider newKey = new RSACryptoServiceProvider();
            newKey.ImportParameters(key.ExportParameters(true));

            return newKey;
        }

        private X509Certificate2 X509()
        {
            return new X509Certificate2("jwt-2048.p12", "1", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }

        private RSACryptoServiceProvider PubKey()
        {
            return (RSACryptoServiceProvider)X509().PublicKey.Key;
        }
        #endregion

        #region mocks

        class MockJsonMapper : JSSerializerMapper, IJsonMapper
        {
            public bool SerializeCalled { get; set; }
            public bool ParseCalled { get; set; }

            public new string Serialize(object obj)
            {
                SerializeCalled = true;
                return base.Serialize(obj);
            }

            public new T Parse<T>(string json)
            {
                ParseCalled = true;
                return base.Parse<T>(json);
            }
        }

        class MockJwsAlgorithm : Plaintext, IJwsAlgorithm
        {
            public bool SignCalled { get; set; }
            public bool VerifyCalled { get; set; }

            public new byte[] Sign(byte[] securedInput, object key)
            {
                SignCalled = true;
                return base.Sign(securedInput, key);
            }

            public new bool Verify(byte[] signature, byte[] securedInput, object key)
            {
                VerifyCalled = true;
                return base.Verify(signature, securedInput, key);
            }
        }

        class MockJweAlgorithm : AesGcmEncryption, IJweAlgorithm
        {
            public MockJweAlgorithm(int keyLength) : base(keyLength) { }

            public bool DecryptCalled { get; set; }
            public bool EncryptCalled { get; set; }

            public new byte[] Decrypt(byte[] aad, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag)
            {
                DecryptCalled = true;
                return base.Decrypt(aad, cek, iv, cipherText, authTag);
            }

            public new byte[][] Encrypt(byte[] aad, byte[] plainText, byte[] cek)
            {
                EncryptCalled = true;
                return base.Encrypt(aad, plainText, cek);
            }
        }

        class MockKeyManagement : DirectKeyManagement, IKeyManagement
        {
            public bool UnwrapCalled { get; set; }
            public bool WrapCalled { get; set; }

            public new byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
            {
                UnwrapCalled = true;
                return base.Unwrap(encryptedCek, key, cekSizeBits, header);
            }

            public new byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
            {
                WrapCalled = true;
                return base.WrapNewKey(cekSizeBits, key, header);
            }
        }

        class MockCompression : DeflateCompression, ICompression
        {
            public bool CompressCalled { get; set; }
            public bool DecompressCalled { get; set; }

            public new byte[] Compress(byte[] plainText)
            {
                CompressCalled = true;
                return base.Compress(plainText);
            }

            public new byte[] Decompress(byte[] compressedText)
            {
                DecompressCalled = true;
                return base.Decompress(compressedText);
            }
        }

        #endregion
    }
}