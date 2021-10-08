using Jose;
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

        //TODO
        public void RsaKey()
        {
            var key = new JWK();
        }

        # region test utils
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

        # endregion
    }
}
