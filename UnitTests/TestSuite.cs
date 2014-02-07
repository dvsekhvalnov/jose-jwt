using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Json;
using NUnit.Framework;
namespace UnitTests
{
    [TestFixture]
    public class TestSuite
    {
        private string key = "a0a2abd8-6162-41c3-83d6-1cf559b46afc";

        [SetUp]
        public void SetUp() {}

        [Test]
        public void DecodePlaintext()
        {
            //given
            string token = "eyJhbGciOiJub25lIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.";

            //when
            var test= (IDictionary<string,object>) Json.JWT.Decode(token,true);

            //then
            Assert.That(test, Is.EqualTo(new Dictionary<string,object>{ {"hello","world"} }));
        }

        [Test]
        public void EncodePlaintext()
        {
            //given
            var payload = new {
                                hello="world"
                              };
            //when
            string hashed = Json.JWT.Encode(payload, JwsAlgorithm.none);

            Console.Out.WriteLine(hashed);

            //then
            Assert.That(hashed,Is.EqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJoZWxsbyI6IndvcmxkIn0."));
        }

        [Test]
        public void DecodeHS256()
        {
            //given
            string token =
                "eyJhbGciOiJIUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.chIoYWrQMA8XL5nFz6oLDJyvgHk2KA4BrFGrKymjC8E";

            //when
            string json = (string) Json.JWT.Decode(token, key);

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""hello"": ""world""}"));
        }

        [Test]
        public void DecodeHS384()
        {
            //given
            string token ="eyJhbGciOiJIUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.McDgk0h4mRdhPM0yDUtFG_omRUwwqVS2_679Yeivj-a7l6bHs_ahWiKl1KoX_hU_";

            //when
            string json = (string) Json.JWT.Decode(token, key);

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""hello"": ""world""}"));
        }

        [Test]
        public void DecodeHS512()
        {
            //given
            string token = "eyJhbGciOiJIUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.9KirTNe8IRwFCBLjO8BZuXf3U2ZVagdsg7F9ZsvMwG3FuqY9W0vqwjzPOjLqPN-GkjPm6C3qWPnINhpr5bEDJQ";

            //when
            string json = (string) Json.JWT.Decode(token, key);

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""hello"": ""world""}"));
        }

        [Test]
        public void DecodeRS256()
        {
            //given
            string token = "eyJhbGciOiJSUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.NL_dfVpZkhNn4bZpCyMq5TmnXbT4yiyecuB6Kax_lV8Yq2dG8wLfea-T4UKnrjLOwxlbwLwuKzffWcnWv3LVAWfeBxhGTa0c4_0TX_wzLnsgLuU6s9M2GBkAIuSMHY6UTFumJlEeRBeiqZNrlqvmAzQ9ppJHfWWkW4stcgLCLMAZbTqvRSppC1SMxnvPXnZSWn_Fk_q3oGKWw6Nf0-j-aOhK0S0Lcr0PV69ZE4xBYM9PUS1MpMe2zF5J3Tqlc1VBcJ94fjDj1F7y8twmMT3H1PI9RozO-21R0SiXZ_a93fxhE_l_dj5drgOek7jUN9uBDjkXUwJPAyp9YPehrjyLdw";


            //when
            string json = (string) Json.JWT.Decode(token, PubKey());

            Console.Out.WriteLine("json = {0}", json);

            //then
            Assert.That(json, Is.EqualTo(@"{""hello"": ""world""}"));
        }

        [Test]
        public void DecodeRS384()
        {
            //given
            string token = "eyJhbGciOiJSUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.cOPca7YEOxnXVdIi7cJqfgRMmDFPCrZG1M7WCJ23U57rAWvCTaQgEFdLjs7aeRAPY5Su_MVWV7YixcawKKYOGVG9eMmjdGiKHVoRcfjwVywGIb-nuD1IBzGesrQe7mFQrcWKtYD9FurjCY1WuI2FzGPp5YhW5Zf4TwmBvOKz6j2D1vOFfGsogzAyH4lqaMpkHpUAXddQxzu8rmFhZ54Rg4T-jMGVlsdrlAAlGA-fdRZ-V3F2PJjHQYUcyS6n1ULcy6ljEOgT5fY-_8DDLLpI8jAIdIhcHUAynuwvvnDr9bJ4xIy4olFRqcUQIHbcb5-WDeWul_cSGzTJdxDZsnDuvg";

            //when
            string json = (string) Json.JWT.Decode(token, PubKey());

            Console.Out.WriteLine("json = {0}", json);

            //then
            Assert.That(json, Is.EqualTo(@"{""hello"": ""world""}"));
        }

        [Test]
        public void DecodeRS512()
        {
            //given
            string token = "eyJhbGciOiJSUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.cOPca7YEOxnXVdIi7cJqfgRMmDFPCrZG1M7WCJ23U57rAWvCTaQgEFdLjs7aeRAPY5Su_MVWV7YixcawKKYOGVG9eMmjdGiKHVoRcfjwVywGIb-nuD1IBzGesrQe7mFQrcWKtYD9FurjCY1WuI2FzGPp5YhW5Zf4TwmBvOKz6j2D1vOFfGsogzAyH4lqaMpkHpUAXddQxzu8rmFhZ54Rg4T-jMGVlsdrlAAlGA-fdRZ-V3F2PJjHQYUcyS6n1ULcy6ljEOgT5fY-_8DDLLpI8jAIdIhcHUAynuwvvnDr9bJ4xIy4olFRqcUQIHbcb5-WDeWul_cSGzTJdxDZsnDuvg";

            //when
            string json = (string) Json.JWT.Decode(token, PubKey());

            Console.Out.WriteLine("json = {0}", json);

            //then
            Assert.That(json, Is.EqualTo(@"{""hello"": ""world""}"));
        }

        [Test]
        public void EncodeHS256()
        {
            //given
            string token = @"{""hello"": ""world""}";

            //when
            string hashed=Json.JWT.Encode(token, key, JwsAlgorithm.HS256);

            //then
            Console.Out.WriteLine("hashed = {0}", hashed);

            Assert.That(hashed, Is.EqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.IntcImhlbGxvXCI6IFwid29ybGRcIn0i.hUqBEt3MRgc89LbU_qDCRQbhrSMSZ2QwbG5-5PU8tiI"));
        }

        [Test]
        public void EncodeHS384()
        {
            //given
            string token = @"{""hello"": ""world""}";

            //when
            string hashed=Json.JWT.Encode(token, key, JwsAlgorithm.HS384);

            //then
            Console.Out.WriteLine("hashed = {0}", hashed);

            Assert.That(hashed, Is.EqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.IntcImhlbGxvXCI6IFwid29ybGRcIn0i.dGhs1ESDC2lpoRy1K-z3n0yQsUlm4Vws7aVp6LXTVhJ_9C0xQwc6ztxNc3Ja-P8q"));
        }

        [Test]
        public void EncodeHS512()
        {
            //given
            string token = @"{""hello"": ""world""}";

            //when
            string hashed=Json.JWT.Encode(token, key, JwsAlgorithm.HS512);

            //then
            Console.Out.WriteLine("hashed = {0}", hashed);

            Assert.That(hashed, Is.EqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.IntcImhlbGxvXCI6IFwid29ybGRcIn0i.bm3KkSKH5eswhvP9FB7h13_WiJ-N4gCRvX5jxuGAFS6O03jO8rQ_mNfqJ2AQ1UOikoZPbjMb1AlJtht2ffvR6A"));
        }

        [Test]
        public void EncodeRS256()
        {
            //given
            string token = @"{""hello"": ""world""}";

            //when
            string hashed=Json.JWT.Encode(token, PrivKey(), JwsAlgorithm.RS256);

            //then
            Console.Out.WriteLine("hashed = {0}", hashed);

            Assert.That(hashed, Is.EqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.IntcImhlbGxvXCI6IFwid29ybGRcIn0i.pTyJsvJNvGbsAZxms9RRGfkemW6r44uesjf-V4uT9H_EDCErnIifcdRUIpCCRjwGFp8n019-oRZttY6f4edxMiXu7Giq1mON5pBKfKENRFmFeFm6klS83h1m33zp_cfXAQk4pWt6LRQUnpuRrAV_nJ88ra5TnBzPq6Cfs5QJn6B9UuE86cXOrirBaiLnx9AWphPtL19sodqHF_bXDCS0qeJ_RaEDiQieWo2ZsIOh0elYSoC3Jgxxp3fqW6eBaBgglTxskh-GarMWvTPG_WHdfw_OKHrMgan8XYl7Vv-_NE4Uz97sXed1GZ247VdRULUIlLYSYfznrgK5J3NdJzwjNQ"));
        }

        [Test]
        public void EncodeRS384()
        {
            //given
            string token = @"{""hello"": ""world""}";

            //when
            string hashed=Json.JWT.Encode(token, PrivKey(), JwsAlgorithm.RS384);

            //then
            Console.Out.WriteLine("hashed = {0}", hashed);

            Assert.That(hashed, Is.EqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.IntcImhlbGxvXCI6IFwid29ybGRcIn0i.SgD2wzM67mXVNdJvRO3SGOY0ffzMFHrUURKNk2CCMd5Me_tQCAXYKGqMzsdkFhY0resqKTv423EXJ9Hzxg5_4P91BI0Qb7j-ei3xR9gtpbTNpwhF_ttwVgKdvKejo5m1sTawsA3SLBPRpqdArpnpqKAVniATWu6LC2_zDmtYQKVvEYN4-6d620PUWhSuUNskWHRLqSdea-e6K2dK6d39sNzvH-qglBAcCmoNO7zy2tlwMkMhNn_baHHMk1kJTk79W3p4fveaLrWmP42s3Ds_Rr4ZQF8T0svYZsFy7vpwZC1ITJRMOPHllqThSJoAtTtVGgi2Exw8uUOJdohxfuaseg"));
        }

        [Test]
        public void EncodeRS512()
        {
            //given
            string token = @"{""hello"": ""world""}";

            //when
            string hashed=Json.JWT.Encode(token, PrivKey(), JwsAlgorithm.RS512);

            //then
            Console.Out.WriteLine("hashed = {0}", hashed);

            Assert.That(hashed, Is.EqualTo("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.IntcImhlbGxvXCI6IFwid29ybGRcIn0i.e9yrjhZ6KFbtiUGH5Kz2oJXUFedqr1ou1WvO50VQ3oQYH2HsTRDp7JJEoXGEBp1l8QTEplm-RxBBGE_OnE2kWYCS1IJy40NHrcjxECHhO4xDZT9WGbAkrmbzuZDeKHmcHVXLGl_AGVROu6IFh_Jka6i6yqMH34N3a4j1-sHs01DO_99Sunx8Cywx-rAT7khu3zgH-aH5GpAge2LyNUxxcJkwwgDOT2-n6pLYg1RaH3S1rgjg5nx0ouD8auwQq5z7sCnYVozsfEG3EQNFcR2VxOF0zqPcQ8FfTV73qeXNPiZZjgmtYiNJOf8Owkt_SE3oKE5XvexiWtWGYCWjxmM0XQ"));
        }

        [Test]
        public void Decrypt_RSA_OAEP_A128CBC_HS256()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.dgIoddBRTBLi8b6fwjaIU5uUP_J-6jL5AtIvoNZDwN0JSmsXkm9SIFz7kQfwavBz_PPG6h0yId55YVFnCqrB5qCIbifmBQPEcB5acKCybHuoHhEBCnQpqxVtHLXZ0dUyd6Xs5h9ymgbbZMjpAoCUK7si90m4O5BCSdedZNQvdXWQW599CRftFVVe_mZOcgABuNIDMfIwyxmi2DVR5c2bSA0ji2Sy27SE_X0lCVHqrAwI-8Rlz1WTWLI6bhRh2jsUPK-6958E4fsXOWsTOp9fW97eW85InZPniv8B5HSG_D0NALhu5AIMsNt-ENeR0sefcphZGUzfyFoxK7EMpY7gAQ.jNw5xfYCvwHvviSuUFYpfw.0_Rvs5cA_QKSVMGbPr5ntFrd_BQhTql-hB9fzLhndAy9vLeHBLtv-bXeZatw4QJIufnpsSnXmRYjKqvWVCp-x-AKpPWzkaj6fvsQ8Mns1kWw5XZr-8SJrbT72LOnRBcTd4qjOYXEJZad8uIwQHDFkkmpm4d7FQ6PhW0-1gOS8FGuYjUupYDQX2ia-4jzqWisv2bE-mKn65q5wy_dT0w04rF-Mk_USyOG5d09kne3ZBv42stpS_xyDS3euVtPuxhQT5TzfPpBkG3CNwwm_HvTTg.E2opVK9nQXPXJbDKb06FBg";

            //when
            string json = (string) Json.JWT.Decode(token,PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""03ac026e-55aa-4475-a806-f09e83048922"",""iat"":1391196068}"));
        }

        [Test]
        public void Decrypt_RSA_OAEP_A256CBC_HS512()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ.gCLatpLEIHdwqXGNQ6pI2azteXmksiGvHZoXaFmGjvN6T71ky5Ov8DHmXyaFdxWVPxiPAf6RDpJlokSR34e1W9ey0m9xWELJ_hH_bEoH4s7-wI74edS06i35let0YvCubl3eIemuQNkaJEqoEaHx8sLZ-SsoRxi7tRAIABl4f_THC8CDLw7SXrVcp_b6xRtB9oSI2_y_vSAZXOTZPJBw_t4jwZLnsOUbBXXGKAGIpG0rrL8qMt1KwRW_79qQie2U1kDclD7EVMQ-ji5upayxaXOMLkPqfISgvyGKyaLs-8e_aRyVKbMpkCZNWaLnSAA6aJHynNsnuM8O4iEN-wRXmw.r2SOQ2k_YqZRpoIB6wSbqA.DeYxdBzfRiiJeAm8H58SO8NJCa4yg3beciqZRGiAqQDrFYdp9q1RHuNrd0UY7DfzBChW5Gp37FqMA3eRpZ_ERbMiYMSgBtqJgUTKWyXGYItThpg92-1Nm7LN_Sp16UOSBHMJmbXeS30NMEfudgk3qUzE2Qmec7msk3X3ylbgn8EIwSIeVpGcEi6OWFCX1lTIRm1bqV2JDxY3gbWUB2H2YVtgL7AaioMttBM8Mm5plDY1pTHXZzgSBrTCtqtmysCothzGkRRzuHDzeaWYbznkVg.Hpk41zlPhLX4UQvb_lbCLZ0zAhOI8A0dA-V31KFGs6A";

            //when
            string json = (string) Json.JWT.Decode(token,PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""19539b79-e5cf-4f99-a66e-00a980e1b0a9"",""iat"":1391196068}"));
        }

        [Test]
        public void Decrypt_RSA_OAEP_A192CBC_HS384()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ.BZ8MgMgby05auOw-Gb4ii-fgcRWAlCHd6pMZNFafle6BAT1accRGUsMGRzJRETUFFqoy3rzfdSdFcqgc7lmUQUXrVei6XCRei5VZJo1YlzIPN9rEig3sSJ99hg1mrXh3ezFX_JczTn7xEaRRzdatnkSvWBMMmbMWVjqlpkXSOr7P7x2Ctf-GQwXOKEVUrRFwe2D0qXC0ynWKrm7mkV-tlRHJf5NRdWLT5Tmxka8OJZ0W1MyJKNEemEMt1dThcnedPMBjb8y0IwPZ8Aiam87fWdqk20MDknNyxRoC_epBFZFaWFpZ383mKI2Ev-EqO2lCnFOkSvwcNmhnlOPXHJ40qQ.1aAvdZ8g580VUE55RqRBVw.IkoVJF73DSzi-ebiErrCAtpWPepbFZS6DX0S9Ka85aRfgmLQRQxBucxm48MixkRJ5QYCPGmtXRPyiQQE9zT1aA5Js6BoV8U2JK44HWga4cNkyUUr0Wpu0uz6GEBU620i9DmJasTb4iA3iTMboCpdrCTlzhJrYhSYc09Jo0WJRM83LjorxRjpUmLGqR4SgV1WYFKaben4iSqOVPThzQc7HEGrkbycZRNKj-BAkll7qRtN_1e5k83W9Wlf5taAWwSXMF2VL6XqR0bZXpPcpLi_vw.kePqK6KpRWohWEpSg8vfeCd0PQAqBmjW";

            //when
            string json = (string) Json.JWT.Decode(token,PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""59f54c91-5224-4484-9c3a-e57b87b6f212"",""iat"":1391196068}"));
        }

        [Test]
        public void Decrypt_RSA_1_5_A128CBC_HS256()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";

            //when
            string json = (string) Json.JWT.Decode(token,PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""3814fff3-db66-45d9-a29a-d2cc2407bdcf"",""iat"":1391196068}"));
        }

        [Test]
        public void Decrypt_RSA_1_5_A192CBC_HS384()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.ApUpt1SGilnXuqvFSHdTV0K9QKSf0P6wEEOTrAqWMwyEOLlyb6VR8o6fdd4wXMTkkL5Bp9BH1x0oibTrVwVa50rxbPDlRJQe0yvBm0w02nkzl3Tt4fE3sGjEXGgI8w8ZxSVAN0EkaXLqzsG1rQ631ptzqyNzg9BWfy53cHhuzh9w00ZOXZtNc7GFBQ1LRvhK1EyLS2_my8KD091KwsjvXC-_J0eOp2W8NkycP_jCIrUzAOSwz--NZyRXt9V2o609HGItKajHplbE1PJVShaXO84MdJl3X6ef8ZXz7mCP3dRlsYfK-tlnFVeEKwC1Oy_zdFsdiY4j41Mj3usvG2j7xQ.GY4Em2zkSGMZsDLNr9pnDw.GZYJSpeQHmOtx34dk4WxEPCnt7l8R5oLKd3IyoMYbjZrWRtomyTufOKfiOVT-nY9ad0Vs5w5Imr2ysy6DnkAFoOnINV_Bzq1hQU4oFfUd_9bFfHZvGuW9H-NTUVBLDhok6NHosSBaY8xLdwHL_GiztRsX_rU4I88bmWBIFiu8T_IRskrX_kSKQ_iGpIJiDy5psIxY4il9dPihLJhcI_JqysW0pIMHB9ij_JSrCnVPs4ngXBHrQoxeDv3HiHFTGXziZ8k79LZ9LywanzC0-ZC5Q.1cmUwl7MnFl__CS9Y__a8t5aVyI9IKOY";

            //when
            string json = (string) Json.JWT.Decode(token,PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""c9d44ff8-ff1e-4490-8454-941e45766152"",""iat"":1391196068}"));
        }

        [Test]
        public void Decrypt_RSA_1_5_A256CBC_HS512()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.GVXwkd5rfqffr4ue26IGHXuiV6r-rQa9OQ4B1LtodsTpWfraOLyhyHYseEKpXV4aSMWWN0q2HS0myj73BuGsDMP-xiIM04QxWD7dbP2OticXzktcHHhMFUx0OK_IOmc21qshTqbb0yKWizMnCuVosQqw2tg_up2sgjqIyiwzpgvC5_l9ddxnTBV334LF_nXTnL22vqrUO92rH_3YmoJ6khHUYVSXhd0fXTKqwm9liULW43prDWkex0N8a8MfgdaFPq0rGw4gRA8HvS7aFn3xCeKAO9Q_q-g32DCDwbfqYhvGZCbS49ObwfPD-fKaFS94VFSMb_Cy-WalZwrIz-aWkQ.zh6hViRORvk4b-2io1vUSA.Us26-89QEOWb85TsOZJpH6QB5_GR3wZo49rR38X1daG_kmyfzIUQQ12wBwmxFwHluNvqStVj4YUIvPgC4oZEh1L-r3Tm81Q2PctdMrwl9fRDR6uH1Hqfx-K25vEhlk_A60s060wezUa5eSttjwEHGTY0FpoQvyOmdfmnOdtW_LLyRWoRzmGocD_N4z6BxK-cVTbbTvAYVbWaZNW_eEMLL4qAnKNAhXJzAtUTqJQIn0Fbh3EE3j827hKrtcRbrwqr1BmoOtaQdYUO4VZKIJ7SNw.Zkt6yXlSu9BdknCr32uyu7uH6HVwGFOV48xc4Z7wF9Y";

            //when
            string json = (string) Json.JWT.Decode(token,PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""7efcdbc6-b2b5-4480-985d-bdf741b376bb"",""iat"":1391196068}"));
        }

        [Test]
        public void Encrypt_RSA_OAEP_A128CBC_HS256()
        {
            //given
            string json =
                @"{""exp"":1389189552,""sub"":""alice"",""nbf"":1389188952,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""e543edf6-edf0-4348-8940-c4e28614d463"",""iat"":1389188952}";

            //when
            string token = Json.JWT.Encode(json, PubKey(), JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);

            //then
            Console.Out.WriteLine("token = {0}", token);

            string[] parts = token.Split('.');

            Assert.That(parts.Length,Is.EqualTo(5),"Make sure 5 parts");
            Assert.That(parts[0], Is.EqualTo("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"),"Header is non-encrypted and static text");
            Assert.That(parts[1].Length, Is.EqualTo(342),"CEK size");
            Assert.That(parts[2].Length, Is.EqualTo(22),"IV size");
            Assert.That(parts[3].Length, Is.EqualTo(278),"cipher text size");
            Assert.That(parts[4].Length, Is.EqualTo(22),"auth tag size");
        }

        [Test]
        public void Encrypt_RSA_OAEP_A192CBC_HS384()
        {
            //given
            var payload = new {
                               exp = 1389189552,
                               sub = "alice",
                               nbf = 1389188952,
                               aud = new[] {@"https:\/\/app-one.com", @"https:\/\/app-two.com"},
                               iss = @"https:\/\/openid.net",
                               jti = "e543edf6-edf0-4348-8940-c4e28614d463",
                               iat = 1389188952
                           };

            //when
            string token = Json.JWT.Encode(payload, PubKey(), JweAlgorithm.RSA_OAEP, JweEncryption.A192CBC_HS384);

            //then
            Console.Out.WriteLine("token = {0}", token);

            string[] parts = token.Split('.');

            Assert.That(parts.Length,Is.EqualTo(5),"Make sure 5 parts");
            Assert.That(parts[0], Is.EqualTo("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"), "Header is non-encrypted and static text");
            Assert.That(parts[1].Length, Is.EqualTo(342),"CEK size");
            Assert.That(parts[2].Length, Is.EqualTo(22),"IV size");
            Assert.That(parts[3].Length, Is.EqualTo(278),"cipher text size");
            Assert.That(parts[4].Length, Is.EqualTo(32),"auth tag size");
        }

        [Test]
        public void Encrypt_RSA_OAEP_A256CBC_HS512()
        {
            //given
            var payload = new
            {
                exp = 1389189552,
                sub = "alice",
                nbf = 1389188952,
                aud = new[] { @"https:\/\/app-one.com", @"https:\/\/app-two.com" },
                iss = @"https:\/\/openid.net",
                jti = "e543edf6-edf0-4348-8940-c4e28614d463",
                iat = 1389188952
            };

            //when            
            string token = Json.JWT.Encode(payload, PubKey(), JweAlgorithm.RSA_OAEP, JweEncryption.A256CBC_HS512);

            //then
            
            Console.Out.WriteLine("token = {0}", token);

            string[] parts = token.Split('.');

            Assert.That(parts.Length,Is.EqualTo(5),"Make sure 5 parts");
            Assert.That(parts[0], Is.EqualTo("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"), "Header is non-encrypted and static text");
            Assert.That(parts[1].Length, Is.EqualTo(342),"CEK size");
            Assert.That(parts[2].Length, Is.EqualTo(22),"IV size");
            Assert.That(parts[3].Length, Is.EqualTo(278),"cipher text size");
            Assert.That(parts[4].Length, Is.EqualTo(43),"auth tag size");
        }

        [Test]
        public void Encrypt_RSA1_5_A128CBC_HS256()
        {
            //given
            string json =
                @"{""exp"":1389189552,""sub"":""alice"",""nbf"":1389188952,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""e543edf6-edf0-4348-8940-c4e28614d463"",""iat"":1389188952}";

            //when
            string token = Json.JWT.Encode(json, PubKey(), JweAlgorithm.RSA1_5, JweEncryption.A128CBC_HS256);

            //then
            Console.Out.WriteLine("token = {0}", token);

            string[] parts = token.Split('.');

            Assert.That(parts.Length, Is.EqualTo(5), "Make sure 5 parts");
            Assert.That(parts[0], Is.EqualTo("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"), "Header is non-encrypted and static text");
            Assert.That(parts[1].Length, Is.EqualTo(342), "CEK size");
            Assert.That(parts[2].Length, Is.EqualTo(22), "IV size");
            Assert.That(parts[3].Length, Is.EqualTo(278), "cipher text size");
            Assert.That(parts[4].Length, Is.EqualTo(22), "auth tag size");
        }

        [Test]
        public void Encrypt_RSA1_5_A192CBC_HS384()
        {
            //given
            var payload = new
            {
                exp = 1389189552,
                sub = "alice",
                nbf = 1389188952,
                aud = new[] { @"https:\/\/app-one.com", @"https:\/\/app-two.com" },
                iss = @"https:\/\/openid.net",
                jti = "e543edf6-edf0-4348-8940-c4e28614d463",
                iat = 1389188952
            };

            //when
            string token = Json.JWT.Encode(payload, PubKey(), JweAlgorithm.RSA1_5, JweEncryption.A192CBC_HS384);

            //then
            Console.Out.WriteLine("token = {0}", token);

            string[] parts = token.Split('.');

            Assert.That(parts.Length, Is.EqualTo(5), "Make sure 5 parts");
            Assert.That(parts[0], Is.EqualTo("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0"), "Header is non-encrypted and static text");
            Assert.That(parts[1].Length, Is.EqualTo(342), "CEK size");
            Assert.That(parts[2].Length, Is.EqualTo(22), "IV size");
            Assert.That(parts[3].Length, Is.EqualTo(278), "cipher text size");
            Assert.That(parts[4].Length, Is.EqualTo(32), "auth tag size");
        }

        [Test]
        public void Encrypt_RSA1_5_A256CBC_HS512()
        {
            //given
            string json =
                @"{""exp"":1389189552,""sub"":""alice"",""nbf"":1389188952,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""e543edf6-edf0-4348-8940-c4e28614d463"",""iat"":1389188952}";

            //when
            string token = Json.JWT.Encode(json, PubKey(), JweAlgorithm.RSA1_5, JweEncryption.A256CBC_HS512);

            //then
            Console.Out.WriteLine("token = {0}", token);

            string[] parts = token.Split('.');

            Assert.That(parts.Length, Is.EqualTo(5), "Make sure 5 parts");
            Assert.That(parts[0], Is.EqualTo("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0"), "Header is non-encrypted and static text");
            Assert.That(parts[1].Length, Is.EqualTo(342), "CEK size");
            Assert.That(parts[2].Length, Is.EqualTo(22), "IV size");
            Assert.That(parts[3].Length, Is.EqualTo(278), "cipher text size");
            Assert.That(parts[4].Length, Is.EqualTo(43), "auth tag size");
        }

        [Test]
        public void Decrypt_RSA_OAEP_A128GCM()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.Izae78a1L2Z0ai_aYbvVbWjiZwz3DTlD27c4Jh44SZAz7T_w7GHiWGuxa4CYPq4Ul_9i5qpdUK1WJOTxlL8C-TXbWzxgwhs-DdmkRBmI5JWozc6RIYz2ddYBIPDTpOSbg_nwVzCUkqId6PwATSPiYjLY0ZwsSung1JGuSKU5WHzdCLh8cXKFdSNo4PA6xxuIFqDWNeshSvbUhK-xPL_ySPSLGtMfzUocPi--SDnc867a92WZpnCwLbpAqlGcj1u-nrpXjlTdECbZbPH5mggnIU8Xrzi6OIRTf2RPOxk2nYcW-KkzsERSUUmoIStaTnnq6MzRLKdF-eOolVaPEB94tQ.dBju23LfGAmbhKQl.l-hxA-_Jj9X-Kbq6W_7XNSxeeDaZc_YFoHRIBclWn2ebd_1qbZ3Td8aPsxBwe4Mc0KP7JdTnDXH53ajtdo2CQaPIaxNh-ffZkUZCi7o-tM_SRyt1MkUnoxQ5ib4i5lzJNEJyklf7lHQhjUhUa2FKTS1KJvLo0uChw5Gb-Y_7S_BUfOzTDCFQR4XFbpd7ngCWww4skpHEulhBhSr66RGog4wwac_ucfSTKeKxZw0UhHBIZFIAju4zcoN8Abh23JHh0VETiA.FFFvIyv5vq_cE1xIPYn6Wg";

            //when
            string json = (string)Json.JWT.Decode(token, PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391705293,""sub"":""alice"",""nbf"":1391704693,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""2f3b5379-a851-4202-ac9a-85baae41459e"",""iat"":1391704693}"));
        }

        [Test]
        public void Decrypt_RSA_OAEP_A192GCM()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJHQ00ifQ.QUBq_S563qAz9KA1oQDPLQ8Upfaf5XWeLLo6w_BpZRPUUshnSsf5GYmxeakuVCGywv2mKR7pEd0EzzA4vL1l3tc8woftrA_jDSU9lQp_Icuwqg9pzBswv7ofKegK7ch7KhOuWGaeFz6mdoUESHhdEPmhVZwz7ryrKWj_TlL-Cr7UG8MpHWV_bvohdtLReTSqfbUbcT_iSY4Nid7RHca__0dmSWgEM2Sydmesv8KJzuoyI6xgGLCaw_p46GuZ4XhM88scV7doV7f3mEv7AYTDMJz4Q5_8lz_gIDDyloTx3-tC9a9KlDVSC3XkPppfQwwjSt-yWhh9SZmsPIpC_K6ubA.pUr3CK_0cTGIODJx.TBD3RZ2nJGNSns_iOOvruxC2Dr-4SsClKIwPXIt8zIjKtKub8o1lFqaRwlBfyciPNMiCqqocWR8zwyNNDFBIAUYJMBW6SPuFzJv8mrjlV_aRsfFmYjpw9U3-n0u-noYHT5U1FXy6feUY907AIqbcEKkHF0TfjEXLfuKVvJHNjaqS84-UFZqmxN0U2szRCo8-k6omS32pRDwTGgl1Co9yXSBUAXtGoi02uqOKpAFbtxfD8_6P41N7-HK86l94m5x1uNCViQ.9xj6WjYwh4OCUr-GKl7_yQ";

            //when
            string json = (string)Json.JWT.Decode(token, PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391710436,""sub"":""alice"",""nbf"":1391709836,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""6b646d08-2871-4e0d-bfa8-48a9e1bd6de5"",""iat"":1391709836}"));
        }

        [Test]
        public void Decrypt_RSA_OAEP_A256GCM()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.M7PuAabTBMnrudthuZNYWfwkXlv1KVxsSYjpaRmuStqybglofWHK37wWWcF5JMYmJfRjswXlGf-iHjw2aSfGpmTJBdUYYbchMtn2TKnjU03piFaqWN3D9384nq_4NJeRkwwe7uYD3iGDxeemJpJLjqpXj5cXgK5Xd93TtJ-QB9hIpXtyDqOlLdoooMWKG8Y9cIBdbwCza57KzOm1S5and_3E4IgijvtRlqENzeLesH3jT3P2310nDEn60j7eqHCeXWR8lUKMZudVCY7f9lkGpotKQeJpxDG1Sd2EG_GiOK5DwpR_1CimkE3c4y1qUoFM10Pjzf7IqZJL1HBAMHcXxQ.9a8lpyZcMoPi2qJb.TKWSdvz395ZfzsjDV6r9mhMdU5XZ14pCcna5EkoA1wmolDAth9qqYAPJErbfZfUAptbUFDitLlsnnnIIhej-N_42XIQnu14Wz0G-sizAn78jKjf145ckDYt63qaX4SxBW6-SQqSCYV4Nz6t0DUBMLK9UcYsVQ2e3Ur5YvxcnTeFM9FqgUiEz9IiNlsJXwZ1HN-LTp0412YCELxoxUu3Bg7R_GWHx2iUliBnRN4WcvRhYMApI_o3qAoK4StTgCQJu-laPdg.Rztnz6rBQ2aSlDHKORI5AA";

            //when
            string json = (string)Json.JWT.Decode(token, PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391710647,""sub"":""alice"",""nbf"":1391710047,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""0b0f3b1b-8f36-4ee2-b463-54263b4af8b7"",""iat"":1391710047}"));
        }

        [Test]
        public void Decrypt_RSA1_5_A128GCM()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.FojyyzygtFOyNBjzqTRfr9HVHPrvtqbVUt9sXSuU59ZhLlzk7FrirryFnFGtj8YC9lx-IX156Ro9rBaJTCU_dfERd05DhPMffT40rdcDiLxfCLOY0E2PfsMyGQPhI6YtNBtf_sQjXWEBC59zH_VoswFAUstkvXY9eVVecoM-W9HFlIxwUXMVpEPtS96xZX5LMksDgJ9sYDTNa6EQOA0hfzw07fD_FFJShcueqJuoJjILYbad-AHbpnLTV4oTbFTYjskRxpEYQr9plFZsT4_xKiCU89slT9EFhmuaiUI_-NGdX-kNDyQZj2Vtid4LSOVv5kGxyygThuQb6wjr1AGe1g.O92pf8iqwlBIQmXA.YdGjkN7lzeKYIv743XlPRYTd3x4VA0xwa5WVoGf1hiHlhQuXGEg4Jv3elk4JoFJzgVuMMQMex8fpFFL3t5I4H9bH18pbrEo7wLXvGOsP971cuOOaXPxhX6qClkwx5qkWhcTbO_2AuJxzIaU9qBwtwWaxJm9axofAPYgYbdaMZkU4F5sFdaFY8IOe94wUA1Ocn_gxC_DYp9IEAyZut0j5RImmthPgiRO_0pK9OvusE_Xg3iGfdxu70x0KpoItuNwlEf0LUA.uP5jOGMxtDUiT6E3ubucBw";

            //when
            string json = (string)Json.JWT.Decode(token, PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391711317,""sub"":""alice"",""nbf"":1391710717,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""cadf3d33-a109-4829-a869-94a4bfbb4cbf"",""iat"":1391710717}"));
        }

        [Test]
        public void Decrypt_RSA1_5_A192GCM()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyR0NNIn0.f-g3EVuoVHRWRnhuQTa0s4V6kKWdCZrQadK27AcmjYNuBAQL26GpiZe1fBggGdREMjXejQjykDd0GGGzdk3avSLlfOuAHb6D5TJE6DB67v_Fjn29_ky-9L6fZmLUKlHOYbE5H2cnkUk9eI3mT0_VJLfhkh3uOAvs1h31NGBmVcQJOLoyH9fa6nTt1kddubsnkHLMfjS_fm4lKOBv2e1S4fosWYEVM9ylpfL-wSYJYrDtEsy_r9lTv19OmrcjtQoqoF9kZ9bMm7jOcZWiG00nw5Zbo2nze_y-bSngJcA7jIutf0zmFxa9GsIVvseQbqcLYZoiACMqEp0HgPg2xfBPmw.mzEicVwcsRKNKrHs.jW2bcx2pxSK2a8NNZSydArUd3JgRQl_dX5N8i5REBeR7WmtgL9aHXyrGqy9rl-iUb6LZMjMFG4tDqOetJjS48OUzMgvLZH3tui_oL8m9ZHWG-yl079uJZSIWU-icHuWzSjbc4ExPu1IXCcTnBGIjid5PM3HAfmWtVP5Pv0q6qeuvzMXvLG7YcZtuS5dTSu1pZTW7O5BEaxy9AvC0-xr0SlTdEEVCT_kZIprhIT7XiGnuMUztx83AxuO-FYXZeL5iXMW8hQ.H9qkfReSyqgVkiVt53fh-Q";

            //when
            string json = (string)Json.JWT.Decode(token, PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391711482,""sub"":""alice"",""nbf"":1391710882,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""7488a8fc-345a-42c2-971e-a286c14fc5af"",""iat"":1391710882}"));
        }

        [Test]
        public void Decrypt_RSA1_5_A256GCM()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIn0.arMHtbGJv2mi7COD9WTz_FzUPJ8Jq1qUTMc5C3IKGD7RNeV1oiv1AgCPiChTuu-UGA56iGJXbFAE7x2jSFK_foKvRvZxyCKz6Siy18seHoz1iw8gU2A_mMG7IEPVcA8MmbMVawFTXoMdLBeW9CsV_102wmZFeh2S74f80XogE63Nd3VjE3LaSbatnXQxIaD0Meq9ZqrKUFZS5SY-FyKqWrdjH82MZP8lrBLDTkTXx4bkfoZForimE1oIEykanpv-tnAlQNFlqRPJsGy-HtcEoHQ7E1Xkqxg9kULmF4TeqiyQ0HBfXXBbm3pQ43GUPmbFJW-l7W6vDAc9-41BCNChQw.kryfKm1U6NobSiyI.kMQXbCKGdeh_vqj6J7wQ1qP48q4VQv5zGZIJp0FgIlk0Lrv9XP4ExlgYlPb24mr1W43d2rY0OJ9fDgPnoTk_cQ6kpXL3nSBo82yBTBA_g6UyIJ4b1PIOpJv_RANA-b8TwQwGtg0eMr_5il4QQWfB_AxnvCe9CDyTkNo7befER3706xilqm6aHdryZx3Hk6C9hbrSe0xW96uor1Js2b-UWRcCJDFQK5Ux9IAHy2Utqsqv7qDq0Ai5pVQOMjyq3iKmUuOOEg.rqSGPBypVniu58fdHswm7g";

            //when
            string json = (string)Json.JWT.Decode(token, PrivKey());

            //then
            Console.Out.WriteLine("json = {0}", json);

            Assert.That(json, Is.EqualTo(@"{""exp"":1391711482,""sub"":""alice"",""nbf"":1391710882,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""77a31aed-f546-4b1d-ba77-9455a2e0a3d5"",""iat"":1391710882}"));
        }

        private RSACryptoServiceProvider PrivKey()
        {
            var key = (RSACryptoServiceProvider)X509().PrivateKey;

            RSACryptoServiceProvider newKey = new RSACryptoServiceProvider();
            newKey.ImportParameters(key.ExportParameters(true));

            return newKey;
        }

        private RSACryptoServiceProvider PubKey()
        {
            return (RSACryptoServiceProvider) X509().PublicKey.Key;
        }

        private X509Certificate2 X509()
        {
            return new X509Certificate2("jwt-2048.p12", "1", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }
    }

}
