using Jose;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class JwkExampleTest
    {
        private TestConsole Console;

        public JwkExampleTest(ITestOutputHelper output)
        {
            Console = new TestConsole(output);
        }

        [Fact]
        public void EncryptedSymmetricKey()
        {
            Jwk shared = new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            var token = Jose.JWT.Encode(shared.ToJson(JWT.DefaultSettings.JsonMapper), "secret", JweAlgorithm.PBES2_HS512_A256KW, JweEncryption.A256GCM);
            Console.Out.WriteLine(token);
        }

        [Fact]
        public void SymmetricKeyInHeader()
        {
            Jwk shared = new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            var headers = new Dictionary<string, object>
            {
                {"jwk", shared.ToDictionary() }
            };

            var token = JWT.Encode(@"{""hello"": ""world""}", shared, JwsAlgorithm.HS512, headers);

            Console.Out.WriteLine(token);
        }

        [Fact]
        public void VerifyWithSymmetricKeyFromHeader()
        {
            var token = "eyJhbGciOiJIUzUxMiIsImp3ayI6eyJrdHkiOiJvY3QiLCJrIjoiR2F3Z2d1RnlHcldLYXY3QVg0VktVZyJ9fQ.eyJoZWxsbyI6ICJ3b3JsZCJ9.d8HO1eSoqgPbVZPXhsds8o_0fqf4gx0fa99UgQtIapojs52jF7xbCQykrls_sDq6J1ltYOFmJ35Hnv9XfryP1A";

            var key = Jwk.FromDictionary((IDictionary<string, object>)JWT.Headers(token)["jwk"]);

            JWT.Decode(token, key);
        }

        [Fact]
        public void DecodeAndUseSymmetricKey()
        {
            string token = "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMmMiOjgxOTIsInAycyI6Inp3eUF0TElqTXpQM01pQ0giLCJlbmMiOiJBMjU2R0NNIn0.4geBbNNUErAkSiNmUVL23tnH3Jah0B0QkvhAaEcHeUgxRGKmWvkOjg.CCNy7C1HOH-qq5Lo.Uzi9FZ_b8bHenXF7h-D63gZCASdvLA7WqnKRSXwsr7G94SnB5bHiZrUT.l6D2hJSoFPpnXPXLyOloxg";

//            var key = JWK.FromJson(
//                       Jose.JWT.Decode(token, "secret"), JWT.DefaultSettings.JsonMapper);
            var key = Jose.JWT.Decode<Jwk>(token, "secret");

            var test = JWT.Encode(@"{""hello"": ""world""}", key, JwsAlgorithm.HS512);

            Console.Out.WriteLine("key = {0}", key);
            Console.Out.WriteLine("test = {0}", key);
        }

        [Fact]
        public void FetchJwks()
        {
            //var key = new Jwk(
            //    e: "AQAB",
            //    n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q",
            //    p: "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts",
            //    q: "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s",
            //    d: "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ",
            //    dp: "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M",
            //    dq: "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU",
            //    qi: "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g"
            //);

            //var headers = new Dictionary<string, object>();
            //headers["x5t"] = "5hJMjOCG0aFBwPGVCyAhepsmDwI";


            //var token = JWT.Encode(@"{""hello"": ""world""}", key, JwsAlgorithm.RS256, headers);
            //Console.Out.WriteLine(token);

            string keys = @"{
	            ""keys"": [
		        {
			        ""kty"": ""oct"",
			        ""alg"": ""sig"",
			        ""k"": ""GawgguFyGrWKav7AX4VKUg""
		        },
		        {
			        ""kty"": ""RSA"",
			        ""key_ops"": [
				        ""verify"",
				        ""sign""
			        ],
			        ""alg"": ""sig"",
			        ""e"": ""AQAB"",
			        ""n"": ""qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"",
			        ""x5t"": ""5hJMjOCG0aFBwPGVCyAhepsmDwI""
		        },
		        {
			        ""kty"": ""EC"",
			        ""alg"": ""enc"",
			        ""crv"": ""P-256"",
			        ""x"": ""BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk"",
			        ""y"": ""g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU""
		        }
	        ]
        }";

            JwkSet jwks = JwkSet.FromJson(keys, JWT.DefaultSettings.JsonMapper);

            var token = "eyJhbGciOiJSUzI1NiIsIng1dCI6IjVoSk1qT0NHMGFGQndQR1ZDeUFoZXBzbUR3SSJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.TLkZBbQ_iVU6wvve4Ahf6u9HOyPimHC7WqZy01wvCcslOb4FNja0XrtcnervP5yG0fiNX4IGNLD3aCtc06vWZ5ok7KdZdFBC30PX4yPuJOuORLpz4SfTP7qgWcXApqJ9Pc1bHIdB5mGsgK_4qxwrHuWNA6eXXSnY8SUpur92PD0Pt9KDH9Q4f82rIeUC9vec_Kp99HRR99BBN0eApUBcsOBn6q5Fkm1urP1zop8qK3_psm9tPWUUV49wsS4l5pXttcsdcYoRhS1B_ZwS09FKoSNcqi72PcGVyZpdbyMQHddv0ok7SYZgaC2EfKDzGjCEbB_TmHn-WGWVHvr3KC3Zxw";
            var headers = Jose.JWT.Headers(token);

            Jwk pubKey = (
                from key in jwks
                where key.Alg == Jwk.KeyUsage.Signature &&
                        key.KeyOps != null && key.KeyOps.Contains(Jwk.KeyOperations.Verify) &&
                        key.Kty == Jwk.KeyTypes.RSA &&
                        key.X5T == (string)headers["x5t"]
                select key
            ).First();

            var payload = Jose.JWT.Decode(token, pubKey);
            Console.Out.WriteLine(payload);

        }
    }
}
