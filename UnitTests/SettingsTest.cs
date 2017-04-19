using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Security.Cryptography;
using Jose;
using Jose.jwe;
using Xunit;

namespace UnitTests
{
    public class SettingsTest
    {
        private byte[] aes128Key = { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };

        [Fact]
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
            Assert.Equal(token, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJoZWxsbyI6IndvcmxkIn0.");
            Assert.True(jsMapper.SerializeCalled);
        }

        [Fact]
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
            Assert.Equal(test, new Dictionary<string, object> { { "hello", "world" } });
            Assert.True(jsMapper.ParseCalled);
        }

        [Fact]
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
            Assert.Equal(token, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJoZWxsbyI6IndvcmxkIn0.");
            Assert.True(jwsAlg.SignCalled);
        }

        [Fact]
        public void Decode_IJwsAlgorithm_Override()
        {
            //given
            MockJwsAlgorithm jwsAlg = new MockJwsAlgorithm();

            string token = "eyJhbGciOiJub25lIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.";

            //when
            var test = Jose.JWT.Decode<IDictionary<string, object>>(token, settings: new JwtSettings().RegisterJws(JwsAlgorithm.none, jwsAlg));

            //then
            Assert.Equal(test, new Dictionary<string, object> { { "hello", "world" } });
            Assert.True(jwsAlg.VerifyCalled);
        }

        [Fact]
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

            Assert.Equal(Jose.JWT.Decode(token, aes128Key), json);
            Assert.True(encAlg.EncryptCalled);
        }

        [Fact]
        public void Decode_IJweAlgorithm_Override()
        {
            //given            
            MockJweAlgorithm encAlg = new MockJweAlgorithm(128);

            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..yVi-LdQQngN0C5WS.1McwSmhZzAtmmLp9y-OdnJwaJFo1nj_4ashmzl2LhubGf0Jl1OTEVJzsHZb7bkup7cGTkuxh6Vfv10ljHsjWf_URXoxP3stQqQeViVcuPV0y2Q_WHYzTNGZpmHGe-hM6gjDhyZyvu3yeXGFSvfPQmp9pWVOgDjI4RC0MQ83rzzn-rRdnZkznWjbmOPxwPrR72Qng0BISsEwbkPn4oO8-vlHkVmPpuDTaYzCT2ZR5K9JnIU8d8QdxEAGb7-s8GEJ1yqtd_w._umbK59DAKA3O89h15VoKQ";

            //when
            string json = Jose.JWT.Decode(token, aes128Key, settings: new JwtSettings().RegisterJwe(JweEncryption.A128GCM, encAlg));

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.Equal(json, @"{""exp"":1392548520,""sub"":""alice"",""nbf"":1392547920,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""0e659a67-1cd3-438b-8888-217e72951ec9"",""iat"":1392547920}");
            Assert.True(encAlg.DecryptCalled);
        }

        [Fact]
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

            Assert.Equal(Jose.JWT.Decode(token, aes128Key), json);

            Assert.True(keyMgmt.WrapCalled);
        }

        [Fact]
        public void Decode_IKeyManagement_Override()
        {
            //given            
            MockKeyManagement keyMgmt = new MockKeyManagement();
            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..yVi-LdQQngN0C5WS.1McwSmhZzAtmmLp9y-OdnJwaJFo1nj_4ashmzl2LhubGf0Jl1OTEVJzsHZb7bkup7cGTkuxh6Vfv10ljHsjWf_URXoxP3stQqQeViVcuPV0y2Q_WHYzTNGZpmHGe-hM6gjDhyZyvu3yeXGFSvfPQmp9pWVOgDjI4RC0MQ83rzzn-rRdnZkznWjbmOPxwPrR72Qng0BISsEwbkPn4oO8-vlHkVmPpuDTaYzCT2ZR5K9JnIU8d8QdxEAGb7-s8GEJ1yqtd_w._umbK59DAKA3O89h15VoKQ";

            //when
            string json = Jose.JWT.Decode(token, aes128Key, settings: new JwtSettings().RegisterJwa(JweAlgorithm.DIR, keyMgmt));

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.Equal(json, @"{""exp"":1392548520,""sub"":""alice"",""nbf"":1392547920,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""0e659a67-1cd3-438b-8888-217e72951ec9"",""iat"":1392547920}");
            Assert.True(keyMgmt.UnwrapCalled);
        }

        [Fact]
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

            Assert.Equal(Jose.JWT.Decode(token, PrivKey()), json);

            Assert.True(compress.CompressCalled);
        }

        [Fact]
        public void Decode_ICompression_Override()
        {
            //given           
            MockCompression compress = new MockCompression();

            string token = "eyJhbGciOiJSU0EtT0FFUCIsInppcCI6IkRFRiIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.nXSS9jDwE0dXkcGI7UquZBhn2nsB2P8u-YSWEuTAgEeuV54qNU4SlE76bToI1z4LUuABHmZOv9S24xkF45b7Mrap_Fu4JXH8euXrQgKQb9o_HL5FvE8m4zk5Ow13MKGPvHvWKOaNEBFriwYIfPi6QBYrpuqn0BaANc_aMyInV0Fn7e8EAgVmvoagmy7Hxic2sPUeLEIlRCDSGa82mpiGusjo7VMJxymkhnMdKufpGPh4wod7pvgb-jDWasUHpsUkHqSKZxlrDQxcy1-Pu1G37TAnImlWPa9NU7500IXc-W07IJccXhR3qhA5QaIyBbmHY0j1Dn3808oSFOYSF85A9w.uwbZhK-8iNzcjvKRb1a2Ig.jxj1GfH9Ndu1y0b7NRz_yfmjrvX2rXQczyK9ZJGWTWfeNPGR_PZdJmddiam15Qtz7R-pzIeyR4_qQoMzOISkq6fDEvEWVZdHnnTUHQzCoGX1dZoG9jXEwfAk2G1vXYT2vynEQZ72xk0V_OBtKhpIAUEFsXwCUeLAAgjFNY4OGWZl_Kmv9RTGhnePZfVbrbwg.WuV64jlV03OZm99qHMP9wQ";

            //when
            string json = Jose.JWT.Decode(token, PrivKey(), settings: new JwtSettings().RegisterCompression(JweCompression.DEF, compress));

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.Equal(json, @"{""exp"":1392963710,""sub"":""alice"",""nbf"":1392963110,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""9fa7a38a-28fd-421c-825c-8fab3bbf3fb4"",""iat"":1392963110}");
            Assert.True(compress.DecompressCalled);
        }

        #region test utils

        private RSA PrivKey()
        {
            return (RSA)X509().GetRSAPrivateKey();
        }

        private RSA PubKey()
        {
            return (RSA)X509().GetRSAPublicKey();
        }

        private X509Certificate2 X509()
        {
            return new X509Certificate2("jwt-2048.p12", "1", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }

        #endregion

        #region mocks

        class MockJsonMapper : NewtonsoftMapper, IJsonMapper
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