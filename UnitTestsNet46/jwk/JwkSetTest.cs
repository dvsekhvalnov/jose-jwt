using Jose;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class JwkSetTest
    {
        private TestConsole Console;

        public JwkSetTest(ITestOutputHelper output)
        {
            Console = new TestConsole(output);
        }

        [Fact]
        public void ToDictionary_EmptySet()
        {
            //given
            JwkSet keySet = new JwkSet();

            //when
            var test = keySet.ToDictionary();

            //then
            Assert.Equal(1, test.Count);
            List<IDictionary<string, object>> list = (List<IDictionary<string, object>>)test["keys"];
            Assert.Empty(list);
        }

        [Fact]
        public void ToDictionary()
        {
            //given
            JwkSet keySet = new JwkSet(
                new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 }),
                new Jwk(
                    e: "AQAB",
                    n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"
                )
            );

            //when
            var test = keySet.ToDictionary();

            //then
            Assert.Equal(1, test.Count);
            List<IDictionary<string, object>> list = (List<IDictionary<string, object>>)test["keys"];

            Assert.Equal(2, list.Count);
            Assert.Equal("oct", list[0]["kty"]);
            Assert.Equal("GawgguFyGrWKav7AX4VKUg", list[0]["k"]);

            Assert.Equal("RSA", list[1]["kty"]);
            Assert.Equal("AQAB", list[1]["e"]);
            Assert.Equal("qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q", list[1]["n"]);
        }

        [Fact]
        public void ToDictionary_AddKey()
        {
            //given
            JwkSet keySet = new JwkSet();
            keySet.Add(new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 }));
            keySet.Add(new Jwk(
                    e: "AQAB",
                    n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"
                )
            );

            //when
            var test = keySet.ToDictionary();

            //then
            Assert.Equal(1, test.Count);
            List<IDictionary<string, object>> list = (List<IDictionary<string, object>>)test["keys"];

            Assert.Equal(2, list.Count);
            Assert.Equal("oct", list[0]["kty"]);
            Assert.Equal("GawgguFyGrWKav7AX4VKUg", list[0]["k"]);

            Assert.Equal("RSA", list[1]["kty"]);
            Assert.Equal("AQAB", list[1]["e"]);
            Assert.Equal("qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q", list[1]["n"]);
        }

        [Fact]
        public void FromDictionary()
        {
            //given
            var data = new Dictionary<string, object>
            {
                { "keys", new List<object>
                    {
                        new Dictionary<string, object> 
                        {
                            { "kty", "oct" },
                            { "k", "GawgguFyGrWKav7AX4VKUg" }
                        },
                        new Dictionary<string, object> 
                        {
                            { "kty", "RSA" },
                            { "e", "AQAB" },
                            { "n", "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q" }
                        }
                    }
                }
            };

            //when
            var test = JwkSet.FromDictionary(data);

            //then
            Assert.Equal(2, test.Keys.Count);

            Assert.Equal("oct", test.Keys[0].Kty);
            Assert.Equal("GawgguFyGrWKav7AX4VKUg", test.Keys[0].K);
            Assert.Equal("RSA", test.Keys[1].Kty);
            Assert.Equal("AQAB", test.Keys[1].E);
            Assert.Equal("qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q", test.Keys[1].N);
        }

        [Fact]
        public void ToJson()
        {
            //given
            JwkSet keySet = new JwkSet(new List<Jwk>
            {
                new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 }),
                new Jwk(
                    e: "AQAB",
                    n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"
                )
            });

            //when
            var test = keySet.ToJson(JWT.DefaultSettings.JsonMapper);

            //then
            Console.Out.WriteLine(test);
            Assert.Equal(test, @"{""keys"":[{""kty"":""oct"",""k"":""GawgguFyGrWKav7AX4VKUg""},{""kty"":""RSA"",""e"":""AQAB"",""n"":""qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q""}]}");
        }

        [Fact]
        public void FromJson()
        {
            //given
            var json = @"{
	            ""keys"": [
		            {
			            ""kty"": ""oct"",
			            ""k"": ""GawgguFyGrWKav7AX4VKUg""
		            },
		            {
			            ""kty"": ""RSA"",
			            ""e"": ""AQAB"",
			            ""n"": ""qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q""
		            }
	            ]
            }";

            //when
            JwkSet test = JwkSet.FromJson(json, JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal(2, test.Keys.Count);

            Assert.Equal("oct", test.Keys[0].Kty);
            Assert.Equal("GawgguFyGrWKav7AX4VKUg", test.Keys[0].K);
            Assert.Equal("RSA", test.Keys[1].Kty);
            Assert.Equal("AQAB", test.Keys[1].E);
            Assert.Equal("qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q", test.Keys[1].N);
        }

        [Fact]
        public void LinqSearch()
        {
            //given
            Jwk key1 = new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });
            key1.Alg = "sig";

            Jwk key2 = new Jwk(
                    e: "AQAB",
                    n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"
            );
            key2.Alg = "enc";
            key2.KeyOps = new List<string> { "verify", "sign" };
            key2.X5T = "5hJMjOCG0aFBwPGVCyAhepsmDwI";

            Jwk key3 = new Jwk(crv: "P-256",
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU"
                           );
            key3.Alg = "enc";


            JwkSet keySet = new JwkSet(key1, key2, key3);

            Console.Out.WriteLine(keySet.ToJson(JWT.DefaultSettings.JsonMapper));

            //when
            var test = (from key in keySet where key.Alg == "enc" && key.Kty == Jwk.KeyTypes.RSA select key).ToList();

            //then
            Assert.Equal(1, test.Count);
            Assert.Equal(key2, test[0]);
        }
    }
}
