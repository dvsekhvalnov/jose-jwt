using Jose;
using Jose.keys;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class JwkTest
    {
        private TestConsole Console;

        public JwkTest(ITestOutputHelper output)
        {
            Console = new TestConsole(output);
        }

        [Fact]
        public void ToDictionary_OctKey()
        {
            //given
            var key = new JWK(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            //when
            var test = key.ToDictionary();

            //then
            Assert.Equal(2, test.Count);
            Assert.Equal("oct", test["kty"]);
            Assert.Equal("GawgguFyGrWKav7AX4VKUg", test["k"]);
        }

        [Fact]
        public void FromDictionary_OctKey()
        {
            //given
            var data = new Dictionary<string, object>
            { 
                { "kty", "oct" }, 
                { "k", "GawgguFyGrWKav7AX4VKUg" }, 
                { "use", "sig" }, 
            };

            //when
            var test = JWK.FromDictionary(data);

            //then
            Assert.Equal(test.Kty, JWK.KeyTypes.OCT);
            Assert.Equal(test.K, "GawgguFyGrWKav7AX4VKUg");
            Assert.Equal(test.OctKey(), new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });
        }

        [Fact]
        public void ToJson_OctKey()
        {
            //given
            var key = new JWK(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper);

            //then 
            Console.Out.WriteLine(test);

            Assert.Equal(test, @"{""kty"":""oct"",""k"":""GawgguFyGrWKav7AX4VKUg""}");
        }

        [Fact]
        public void FromJson_OctKey()
        {
            //given
            var json = @"{
                ""kty"":""oct"",
                ""use"":""sig"",
                ""k"":""GawgguFyGrWKav7AX4VKUg""
            }";

            //when
            var test = JWK.FromJson(json, JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal(test.Kty, JWK.KeyTypes.OCT);
            Assert.Equal(test.K, "GawgguFyGrWKav7AX4VKUg");
            Assert.Equal(test.OctKey(), new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });
        }

        [Fact]
        public void OctKey()
        {
            //given
            var key = new JWK(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            //then            
            Assert.Equal(key.OctKey(), new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });
            Assert.Equal(key.K, "GawgguFyGrWKav7AX4VKUg");
        }

        [Fact]
        public void ToDictionary_RsaPubKey()
        {
            //given
            var key = new JWK(
                e: "AQAB",
                n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"
            );

            //when
            var test = key.ToDictionary();

            //then
            Assert.Equal(3, test.Count);
            Assert.Equal("RSA", test["kty"]);
            Assert.Equal("AQAB", test["e"]);
            Assert.Equal("qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q", test["n"]);
        }

        [Fact]
        public void ToDictionary_RsaPrivKey()
        {
            //given
            var key = new JWK(
                e: "AQAB",
                n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q",
                p: "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts",
                q: "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s",
                d: "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ",
                dp: "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M",
                dq: "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU",
                qi: "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g"
            );

            //when
            var test = key.ToDictionary();

            //then
            Assert.Equal(9, test.Count);
            Assert.Equal("RSA", test["kty"]);
            Assert.Equal("AQAB", test["e"]);
            Assert.Equal("qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q", test["n"]);

            Assert.Equal("lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ", test["d"]);
            Assert.Equal("0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts", test["p"]);
            Assert.Equal("KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M", test["dp"]);
            Assert.Equal("zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s", test["q"]);
            Assert.Equal("Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU", test["dq"]);
            Assert.Equal("sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g", test["qi"]);
        }

        [Fact]
        public void FromDictionary_RsaKey()
        {
            //given
            var data = new Dictionary<string, object>
            { 
                { "kty", "RSA" },                 
                { "use", "sig" },
                { "e", "AQAB" },
                { "n", "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q" },
                { "p", "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts" },
                { "q", "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s" },
                { "d", "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ" },
                { "dp", "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M" },
                { "dq", "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU" },
                { "qi", "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g" }
            };

            //when
            var test = JWK.FromDictionary(data);

            //then
            Assert.Equal(test.Kty, JWK.KeyTypes.RSA);
            Assert.Equal(test.Use, JWK.Usage.Signature);
            Assert.Equal(test.E, "AQAB");
            Assert.Equal(test.N, "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q");
            Assert.Equal(test.P, "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts");
            Assert.Equal(test.Q, "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s");
            Assert.Equal(test.D, "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ");
            Assert.Equal(test.DP, "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M");
            Assert.Equal(test.DQ, "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU");
            Assert.Equal(test.QI, "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g");

            var key = test.RsaKey();

            Assert.NotNull(key);

            var p = key.ExportParameters(true);

            Assert.NotNull(p);
            Assert.NotNull(p.D);
        }

        [Fact]
        public void ToJson_PublicRsaKey()
        {
            //given
            var key = new JWK(
                e: "AQAB",
                n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"
            );

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper); 

            //then
            Console.Out.WriteLine(test);
            Assert.Equal(test, @"{""kty"":""RSA"",""e"":""AQAB"",""n"":""qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q""}");
        }

        [Fact]
        public void ToJson_PrivateRsaKey()
        {
            //given
            var key = new JWK(
                e: "AQAB",
                n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q",
                p: "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts",
                q: "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s",
                d: "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ",
                dp: "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M",
                dq: "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU",
                qi: "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g"
            );

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper); 

            //then
            Console.Out.WriteLine(test);
            Assert.Equal(test, @"{""kty"":""RSA"",""e"":""AQAB"",""n"":""qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"",""d"":""lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ"",""p"":""0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts"",""q"":""zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s"",""dp"":""KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M"",""dq"":""Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU"",""qi"":""sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g""}");
        }

        [Fact]
        public void FromJson_RsaKey()
        {
            //given
            var json = @"{
	            ""d"": ""lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ"",
	            ""dp"": ""KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M"",
	            ""dq"": ""Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU"",
	            ""e"": ""AQAB"",
	            ""kid"": ""Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc"",
	            ""kty"": ""RSA"",
	            ""n"": ""qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"",
	            ""p"": ""0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts"",
	            ""q"": ""zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s"",
	            ""qi"": ""sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g""
            }";

            //when
            var test = JWK.FromJson(json, JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal(test.Kty, JWK.KeyTypes.RSA);            
            Assert.Equal(test.KeyId, "Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc");
            Assert.Equal(test.E, "AQAB");
            Assert.Equal(test.N, "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q");
            Assert.Equal(test.P, "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts");
            Assert.Equal(test.Q, "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s");
            Assert.Equal(test.D, "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ");
            Assert.Equal(test.DP, "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M");
            Assert.Equal(test.DQ, "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU");
            Assert.Equal(test.QI, "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g");

            var key = test.RsaKey();

            Assert.NotNull(key);

            var p = key.ExportParameters(true);

            Assert.NotNull(p);
            Assert.NotNull(p.D);
        }

        [Fact]
        public void NewRsaPubKey()
        {
            //given
            var test = new JWK(PubRsaKey(), false);

            //then
            Assert.Equal(test.Kty, JWK.KeyTypes.RSA);
            Assert.Equal(test.E, "AQAB");
            Assert.Equal(test.N, "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q");
        }

        [Fact]
        public void NewRsaPrivKey()
        {
            //given
            var test = new JWK(PrivRsaKey());

            //then
            Assert.Equal(test.Kty, JWK.KeyTypes.RSA);
            Assert.Equal(test.E, "AQAB");
            Assert.Equal(test.N, "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q");
            Assert.Equal(test.D, "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ");
            Assert.Equal(test.P, "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts");
            Assert.Equal(test.DP, "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M");
            Assert.Equal(test.Q, "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s");
            Assert.Equal(test.DQ, "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU");
            Assert.Equal(test.QI, "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g");
        }

        [Fact]
        public void RsaKey_Public()
        {
            //given
            var key = new JWK("AQAB", "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q");

            //when
            var test = key.RsaKey();

            RSAParameters p = test.ExportParameters(false);

            //then
            Assert.Equal(p.Exponent, new byte[] { 1, 0, 1 } );
            Assert.Equal(p.Modulus, new byte[] { 168, 86, 111, 210, 151, 154, 254, 57, 249, 50, 142, 42, 17, 73, 146, 182, 232, 101, 186, 91, 40, 242, 125, 98, 157, 118, 196, 162, 215, 127, 205, 58, 208, 167, 210, 180, 68, 173, 33, 127, 187, 116, 43, 128, 99, 41, 88, 90, 138, 162, 26, 155, 139, 85, 85, 11, 228, 153, 135, 129, 121, 138, 245, 50, 105, 206, 255, 67, 125, 237, 211, 1, 207, 254, 223, 154, 252, 175, 210, 24, 7, 104, 23, 80, 230, 100, 121, 187, 114, 211, 148, 122, 60, 182, 52, 68, 239, 225, 179, 102, 97, 172, 234, 51, 28, 202, 62, 199, 109, 122, 27, 12, 244, 9, 102, 154, 141, 203, 162, 99, 150, 32, 213, 95, 21, 188, 157, 98, 67, 122, 220, 70, 6, 90, 166, 78, 61, 68, 213, 250, 246, 68, 43, 25, 46, 183, 131, 56, 244, 131, 33, 231, 70, 214, 234, 115, 245, 26, 218, 74, 27, 8, 15, 55, 158, 124, 231, 10, 137, 183, 0, 104, 167, 158, 84, 141, 235, 144, 5, 60, 254, 99, 154, 184, 180, 151, 191, 126, 225, 150, 77, 33, 234, 196, 173, 37, 189, 234, 101, 5, 242, 57, 73, 21, 146, 53, 200, 146, 27, 205, 187, 251, 222, 210, 254, 203, 136, 180, 248, 27, 243, 177, 96, 108, 233, 57, 7, 2, 158, 41, 138, 118, 136, 243, 52, 254, 134, 181, 80, 218, 48, 248, 126, 66, 68, 137, 19, 125, 148, 10, 139, 61, 71, 124, 8, 217 } );
        }

        [Fact]
        public void RsaKey_Private()
        {
            //given
            var key = new JWK(
                e: "AQAB", 
                n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q",
                p: "0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts",
                q: "zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s",
                d: "lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ",
                dp: "KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M",
                dq: "Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU",
                qi: "sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g"
            );

            //when
            var test = key.RsaKey();

            RSAParameters p = test.ExportParameters(true);

            //then
            Assert.Equal(p.Exponent, new byte[] { 1, 0, 1 } );
            Assert.Equal(p.Modulus, new byte[] { 168, 86, 111, 210, 151, 154, 254, 57, 249, 50, 142, 42, 17, 73, 146, 182, 232, 101, 186, 91, 40, 242, 125, 98, 157, 118, 196, 162, 215, 127, 205, 58, 208, 167, 210, 180, 68, 173, 33, 127, 187, 116, 43, 128, 99, 41, 88, 90, 138, 162, 26, 155, 139, 85, 85, 11, 228, 153, 135, 129, 121, 138, 245, 50, 105, 206, 255, 67, 125, 237, 211, 1, 207, 254, 223, 154, 252, 175, 210, 24, 7, 104, 23, 80, 230, 100, 121, 187, 114, 211, 148, 122, 60, 182, 52, 68, 239, 225, 179, 102, 97, 172, 234, 51, 28, 202, 62, 199, 109, 122, 27, 12, 244, 9, 102, 154, 141, 203, 162, 99, 150, 32, 213, 95, 21, 188, 157, 98, 67, 122, 220, 70, 6, 90, 166, 78, 61, 68, 213, 250, 246, 68, 43, 25, 46, 183, 131, 56, 244, 131, 33, 231, 70, 214, 234, 115, 245, 26, 218, 74, 27, 8, 15, 55, 158, 124, 231, 10, 137, 183, 0, 104, 167, 158, 84, 141, 235, 144, 5, 60, 254, 99, 154, 184, 180, 151, 191, 126, 225, 150, 77, 33, 234, 196, 173, 37, 189, 234, 101, 5, 242, 57, 73, 21, 146, 53, 200, 146, 27, 205, 187, 251, 222, 210, 254, 203, 136, 180, 248, 27, 243, 177, 96, 108, 233, 57, 7, 2, 158, 41, 138, 118, 136, 243, 52, 254, 134, 181, 80, 218, 48, 248, 126, 66, 68, 137, 19, 125, 148, 10, 139, 61, 71, 124, 8, 217 } );
            Assert.Equal(p.D, new byte[] { 148, 152, 112, 111, 74, 74, 148, 29, 162, 191, 32, 197, 59, 171, 97, 106, 58, 45, 10, 90, 204, 3, 121, 241, 34, 36, 164, 33, 70, 239, 86, 191, 147, 78, 129, 109, 133, 173, 250, 131, 33, 122, 195, 167, 186, 96, 213, 208, 94, 206, 7, 132, 196, 114, 215, 246, 254, 157, 20, 3, 147, 193, 184, 253, 254, 110, 173, 223, 234, 250, 147, 167, 230, 238, 10, 126, 106, 141, 221, 124, 62, 149, 128, 247, 117, 216, 189, 168, 93, 13, 45, 228, 213, 80, 213, 69, 1, 39, 143, 208, 81, 106, 108, 246, 31, 116, 220, 3, 248, 188, 175, 194, 56, 109, 79, 248, 32, 48, 224, 48, 222, 102, 47, 83, 151, 1, 127, 62, 190, 222, 227, 221, 134, 93, 194, 193, 1, 66, 78, 12, 14, 185, 223, 193, 3, 218, 118, 48, 243, 20, 28, 111, 54, 192, 194, 191, 176, 211, 181, 35, 68, 216, 166, 57, 187, 78, 124, 13, 7, 8, 138, 108, 199, 254, 139, 144, 138, 158, 234, 33, 130, 134, 43, 16, 54, 11, 120, 200, 55, 127, 125, 158, 6, 88, 229, 8, 83, 88, 106, 128, 173, 79, 233, 171, 213, 151, 180, 57, 50, 77, 15, 78, 47, 109, 242, 232, 181, 95, 129, 4, 171, 165, 34, 150, 206, 57, 39, 149, 164, 161, 187, 128, 156, 89, 30, 107, 251, 138, 126, 207, 19, 159, 214, 205, 172, 74, 21, 90, 7, 91, 124, 17, 234, 255, 198, 205 } );
            Assert.Equal(p.P, new byte[] { 210, 166, 142, 145, 61, 123, 226, 244, 70, 220, 79, 250, 238, 5, 55, 150, 3, 160, 161, 62, 139, 222, 149, 71, 186, 238, 240, 126, 178, 4, 163, 28, 156, 61, 174, 127, 153, 149, 70, 231, 132, 160, 189, 5, 40, 124, 101, 24, 16, 104, 209, 210, 86, 175, 80, 8, 194, 151, 15, 109, 59, 55, 14, 12, 117, 252, 68, 12, 100, 184, 57, 237, 0, 89, 237, 7, 24, 17, 51, 226, 51, 3, 47, 16, 205, 228, 101, 253, 198, 225, 129, 88, 193, 76, 8, 65, 115, 24, 62, 221, 92, 146, 191, 145, 157, 196, 92, 171, 65, 162, 40, 240, 236, 191, 60, 242, 53, 47, 129, 5, 41, 145, 230, 137, 192, 93, 222, 219 } );
            Assert.Equal(p.Q, new byte[] { 204, 147, 234, 8, 50, 170, 104, 145, 253, 76, 1, 159, 206, 222, 155, 225, 163, 109, 245, 250, 98, 172, 71, 29, 164, 1, 117, 108, 39, 157, 21, 244, 38, 81, 147, 52, 44, 109, 235, 50, 211, 128, 34, 24, 196, 94, 0, 3, 183, 145, 129, 241, 147, 74, 220, 20, 37, 240, 18, 114, 50, 98, 172, 231, 186, 10, 153, 181, 92, 56, 49, 17, 10, 211, 234, 140, 64, 151, 94, 204, 71, 249, 172, 253, 159, 60, 90, 180, 251, 220, 111, 184, 166, 21, 111, 14, 149, 107, 37, 194, 190, 8, 33, 18, 157, 18, 60, 196, 98, 206, 44, 201, 2, 115, 238, 77, 164, 182, 163, 169, 96, 142, 127, 81, 246, 39, 195, 91 } );
            Assert.Equal(p.InverseQ, new byte[] { 177, 16, 15, 138, 2, 105, 151, 196, 191, 190, 199, 245, 206, 18, 83, 172, 115, 61, 239, 20, 112, 184, 29, 186, 71, 164, 230, 248, 159, 44, 41, 19, 219, 238, 158, 113, 196, 217, 102, 56, 16, 69, 189, 105, 150, 197, 219, 104, 241, 208, 68, 148, 217, 114, 117, 38, 90, 159, 126, 247, 200, 18, 241, 205, 111, 155, 102, 5, 105, 248, 29, 145, 41, 61, 65, 221, 104, 83, 97, 111, 213, 163, 144, 203, 133, 104, 188, 225, 115, 39, 112, 156, 71, 237, 171, 237, 198, 209, 125, 202, 75, 26, 120, 167, 180, 123, 105, 247, 39, 164, 211, 106, 126, 119, 152, 56, 56, 40, 95, 20, 208, 225, 14, 217, 200, 170, 59, 216 } );
            Assert.Equal(p.DP, new byte[] { 41, 53, 166, 76, 105, 159, 211, 221, 128, 3, 87, 174, 58, 100, 80, 228, 139, 31, 32, 140, 80, 230, 161, 131, 159, 225, 96, 177, 24, 120, 105, 196, 142, 24, 79, 11, 237, 106, 211, 173, 53, 56, 16, 226, 114, 114, 43, 128, 210, 172, 254, 231, 76, 72, 13, 187, 56, 254, 62, 105, 91, 29, 65, 37, 84, 235, 158, 16, 98, 159, 219, 205, 46, 181, 104, 246, 107, 81, 234, 57, 133, 75, 73, 40, 219, 110, 164, 57, 74, 112, 17, 82, 224, 181, 212, 35, 161, 181, 139, 142, 216, 174, 104, 197, 190, 252, 140, 56, 128, 165, 141, 166, 220, 89, 233, 61, 101, 4, 63, 20, 88, 118, 143, 136, 65, 86, 219, 227 } );
            Assert.Equal(p.DQ, new byte[] { 38, 125, 37, 168, 201, 47, 122, 97, 13, 16, 193, 181, 121, 76, 52, 115, 173, 53, 192, 243, 140, 160, 240, 248, 72, 164, 229, 156, 165, 143, 78, 84, 18, 233, 130, 18, 108, 209, 121, 80, 164, 174, 20, 188, 40, 37, 175, 71, 3, 192, 98, 124, 58, 195, 248, 199, 233, 163, 83, 53, 28, 249, 167, 162, 41, 68, 89, 74, 223, 192, 202, 170, 116, 41, 14, 149, 184, 137, 66, 18, 152, 240, 6, 117, 233, 1, 135, 231, 73, 3, 94, 25, 149, 85, 175, 1, 69, 103, 85, 65, 96, 83, 83, 53, 151, 75, 153, 23, 49, 167, 172, 145, 92, 222, 198, 212, 224, 202, 99, 220, 56, 8, 87, 55, 234, 97, 236, 197 } );
        }

        [Fact]
        public void EccKey_Public()
        {
            //given
            var key = new JWK(crv: "P-256", x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU");

            //when
            var test = key.CngKey();

            //then
            Assert.NotNull(test);
            Assert.Equal(key.Crv, "P-256");
            Assert.Equal(test.Algorithm, CngAlgorithm.ECDsaP256);
            Assert.True(test.IsEphemeral);
        }

        [Fact]
        public void EccKey_Private()
        {
            //given
            var key = new JWK(crv: "P-256", 
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", 
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
                              d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
                           );

            //when
            var test = key.CngKey();

            //then
            Assert.NotNull(test);
            Assert.Equal(key.Crv, "P-256");
            Assert.Equal(test.Algorithm, CngAlgorithm.ECDsaP256);
            Assert.True(test.IsEphemeral);
        }

        [Fact]
        public void EccKey_Private_KeyAgreement()
        {
            //given
            var key = new JWK(crv: "P-256", 
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", 
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
                              d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
                           );

            //when
            var test = key.CngKey(CngKeyUsages.KeyAgreement);

            //then
            Assert.NotNull(test);
            Assert.Equal(key.Crv, "P-256");
            Assert.Equal(test.Algorithm, CngAlgorithm.ECDiffieHellmanP256);
            Assert.True(test.IsEphemeral);
        }
        //[Fact]
        //public void NewEccCngPublicKey()
        //{
        //    //given
        //    var test = new JWK(Ecc256Public());

        //    //then
        //    Assert.Equal(test.Kty, JWK.KeyTypes.EC);
        //}

        //[Fact]
        //public void NewEccCngPrivateKey()
        //{
        //    //given
        //    var test = new JWK(Ecc256Private());

        //    //then
        //    Assert.Equal(test.Kty, JWK.KeyTypes.EC);
        //}


        [Fact]
        public void ToDictionary_EccPubKey()
        {
            //given
            var key = new JWK(crv: "P-256",
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU"
                           );

            //when
            var test = key.ToDictionary();

            //then
            Assert.Equal(4, test.Count);
            Assert.Equal("EC", test["kty"]);
            Assert.Equal("P-256", test["crv"]);
            Assert.Equal("BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", test["x"]);
            Assert.Equal("g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU", test["y"]);            
        }

        [Fact]
        public void ToDictionary_EccPrivate()
        {
            //given
            var key = new JWK(crv: "P-256",
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
                              d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
                           );

            //when
            var test = key.ToDictionary();

            //then
            Assert.Equal(5, test.Count);
            Assert.Equal("EC", test["kty"]);
            Assert.Equal("P-256", test["crv"]);
            Assert.Equal("BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", test["x"]);
            Assert.Equal("g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU", test["y"]);            
            Assert.Equal("KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4", test["d"]);            
        }

        [Fact]
        public void FromDictionary_EccKey()
        {
            //given
            var data = new Dictionary<string, object>
            {
                { "kty", "EC" },
                { "use", "enc" },
                { "crv", "P-256" },
                { "x", "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk" },
                { "y", "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU" },
                { "d", "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4" }
            };

            //when
            var test = JWK.FromDictionary(data);

            //then
            Assert.Equal(test.Kty, JWK.KeyTypes.EC);
            Assert.Equal(test.Use, JWK.Usage.Encryption);            
            Assert.Equal(test.Crv, "P-256");            
            Assert.Equal(test.X, "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk");
            Assert.Equal(test.Y, "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU");
            Assert.Equal(test.D, "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4");

            var key = test.CngKey();

            Assert.NotNull(key);            
            Assert.Equal(key.Algorithm, CngAlgorithm.ECDsaP256);
            Assert.True(key.IsEphemeral);
        }

        [Fact]
        public void ToJson_EccPubKey()
        {
            //given
            var key = new JWK(crv: "P-256",
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU"
                           );

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper);

            //then
            Console.Out.WriteLine(test);
            Assert.Equal(test, @"{""kty"":""EC"",""crv"":""P-256"",""x"":""BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk"",""y"":""g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU""}");
        }

        [Fact]
        public void ToJson_EccPrivKey()
        {
            //given
            var key = new JWK(crv: "P-256",
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
                              d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
                           );

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper);

            //then
            Console.Out.WriteLine(test);
            Assert.Equal(test, @"{""kty"":""EC"",""crv"":""P-256"",""x"":""BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk"",""y"":""g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU"",""d"":""KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4""}");
        }

        [Fact]
        public void FromJson_EccKey()
        {
            //given
            var json = @"{
	            ""kty"": ""EC"",
                ""kid"": ""Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc"",
	            ""crv"": ""P-256"",
	            ""use"": ""enc"",
	            ""x"": ""BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk"",
	            ""y"": ""g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU"",
	            ""d"": ""KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4""
            }";

            //when
            var test = JWK.FromJson(json, JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal(test.KeyId, "Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc");
            Assert.Equal(test.Kty, JWK.KeyTypes.EC);
            Assert.Equal(test.Use, JWK.Usage.Encryption);
            Assert.Equal(test.Crv, "P-256");
            Assert.Equal(test.X, "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk");
            Assert.Equal(test.Y, "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU");
            Assert.Equal(test.D, "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4");

            var key = test.CngKey();

            Assert.NotNull(key);

            Assert.NotNull(key);
            Assert.Equal(key.Algorithm, CngAlgorithm.ECDsaP256);
            Assert.True(key.IsEphemeral);
        }

        #region test utils
        private RSA PrivRsaKey()
        {
            return X509().GetRSAPrivateKey();
        }

        private RSA PubRsaKey()
        {
            return X509().GetRSAPublicKey();
        }

        private X509Certificate2 X509()
        {
            return new X509Certificate2("jwt-2048.p12", "1", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }

        private CngKey Ecc256Private(CngKeyUsages usage = CngKeyUsages.Signing)
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EccKey.New(x, y, d, usage);

        }

        private CngKey Ecc256Public(CngKeyUsages usage = CngKeyUsages.Signing)
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EccKey.New(x, y, usage: usage);
        }

        private ECDsa ECDSa256Public()
        {
            var x095 = new X509Certificate2("ecc256.p12", "12345");

            return x095.GetECDsaPublicKey();
        }

        private ECDsa ECDSa256Private()
        {
            var x095 = new X509Certificate2("ecc256.p12", "12345");

            return x095.GetECDsaPrivateKey();
        }

        #endregion
    }
}
