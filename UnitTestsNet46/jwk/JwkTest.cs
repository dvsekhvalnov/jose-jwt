using Jose;
using Jose.keys;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class JwkTest
    {
        private readonly TestConsole Console;

        public JwkTest(ITestOutputHelper output)
        {
            Console = new TestConsole(output);
        }

        [Fact]
        public void ToDictionary_NamedParams()
        {
            //given
            var key = new Jwk();

            key.KeyId = "AA9D2AB0-20B8-4B04-B111-AE0DC118310F";
            key.KeyOps = new List<string>();
            key.KeyOps.Add(Jwk.KeyOperations.Decrypt);
            key.KeyOps.Add(Jwk.KeyOperations.DeriveKey);
            key.KeyOps.Add(Jwk.KeyOperations.Sign);
            key.Alg = "RS256";
            key.Use = Jwk.KeyUsage.Encryption;
            key.Kty = "OKP";
            key.X5U = "https://thetrap.com/main.crt";
            key.X5T = "5hJMjOCG0aFBwPGVCyAhepsmDwI";
            key.X5TSha256 = "uyIuvRrCqDBYz5XIDMk5z1CT5_Gpel_8GylIAFZxRVc";
            key.X5C = new List<string>
            {
                "MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se",
                "MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ=="
            };

            //when
            var test = key.ToDictionary();

            //then
            Assert.Equal(9, test.Count);
            Assert.Equal("OKP", test["kty"]);
            Assert.Equal("RS256", test["alg"]);
            Assert.Equal("enc", test["use"]);
            Assert.Equal("AA9D2AB0-20B8-4B04-B111-AE0DC118310F", test["kid"]);
            Assert.Equal("https://thetrap.com/main.crt", test["x5u"]);
            Assert.Equal("5hJMjOCG0aFBwPGVCyAhepsmDwI", test["x5t"]);
            Assert.Equal("uyIuvRrCqDBYz5XIDMk5z1CT5_Gpel_8GylIAFZxRVc", test["x5t#S256"]);
            Assert.Equal(new[] { "decrypt", "deriveKey", "sign" }, test["key_ops"]);
            Assert.Equal(new List<string>
            {
                "MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se",
                "MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ=="
            }, test["x5c"]);
        }

        [Fact]
        public void ToJson_NamedParams()
        {
            //given
            var key = new Jwk();

            key.KeyId = "AA9D2AB0-20B8-4B04-B111-AE0DC118310F";
            key.KeyOps = new List<string>();
            key.KeyOps.Add(Jwk.KeyOperations.Decrypt);
            key.KeyOps.Add(Jwk.KeyOperations.DeriveKey);
            key.KeyOps.Add(Jwk.KeyOperations.Sign);
            key.Alg = "RS256";
            key.Use = Jwk.KeyUsage.Encryption;
            key.Kty = "OKP";
            key.X5U = "https://thetrap.com/main.crt";
            key.X5T = "5hJMjOCG0aFBwPGVCyAhepsmDwI";
            key.X5TSha256 = "uyIuvRrCqDBYz5XIDMk5z1CT5_Gpel_8GylIAFZxRVc";
            key.X5C = new List<string>
            {
                "MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se",
                "MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ=="
            };

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper);

            //then
            Console.Out.WriteLine(test);
            Assert.Equal(@"{""kty"":""OKP"",""kid"":""AA9D2AB0-20B8-4B04-B111-AE0DC118310F"",""use"":""enc"",""key_ops"":[""decrypt"",""deriveKey"",""sign""],""alg"":""RS256"",""x5u"":""https://thetrap.com/main.crt"",""x5t"":""5hJMjOCG0aFBwPGVCyAhepsmDwI"",""x5t#S256"":""uyIuvRrCqDBYz5XIDMk5z1CT5_Gpel_8GylIAFZxRVc"",""x5c"":[""MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se"",""MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ==""]}", test);
        }

        [Fact]
        public void FromJson_NamedParams()
        {
            //given
            string json = @"{
                ""kty"": ""OKP"",
                ""kid"": ""AA9D2AB0-20B8-4B04-B111-AE0DC118310F"",
                ""use"": ""enc"",
                ""key_ops"": [
                    ""encrypt"",
                    ""wrapKey"",
                    ""sign""
                ],
                ""alg"": ""PS256"",
                ""x5u"": ""https://thetrap.com/main.crt"",
                ""x5t"": ""5hJMjOCG0aFBwPGVCyAhepsmDwI"",
                ""x5t#S256"": ""uyIuvRrCqDBYz5XIDMk5z1CT5_Gpel_8GylIAFZxRVc"",
                ""x5c"": [
                    ""MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se"",
                    ""MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ==""
                ]
            }";

            //when
            var test = Jwk.FromJson(json, JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal("OKP", test.Kty);
            Assert.Equal("AA9D2AB0-20B8-4B04-B111-AE0DC118310F", test.KeyId);
            Assert.Equal("PS256", test.Alg);
            Assert.Equal(Jwk.KeyUsage.Encryption, test.Use);
            Assert.Equal(3, test.KeyOps.Count);
            Assert.Equal(new[] { Jwk.KeyOperations.Encrypt, Jwk.KeyOperations.WrapKey, Jwk.KeyOperations.Sign }, test.KeyOps);
            Assert.Equal("https://thetrap.com/main.crt", test.X5U);
            Assert.Equal("5hJMjOCG0aFBwPGVCyAhepsmDwI", test.X5T);
            Assert.Equal("uyIuvRrCqDBYz5XIDMk5z1CT5_Gpel_8GylIAFZxRVc", test.X5TSha256);
            Assert.Equal(new List<string>
            {
                "MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se",
                "MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ=="
            }, test.X5C);

            Assert.Null(test.OtherParams);
        }

        [Fact]
        public void FromDictionary_NamedParams()
        {
            //given
            var data = new Dictionary<string, object>
            {
                { "kty", "OKP" },
                { "use", "sig" },
                { "alg", "PS256" },
                { "kid", "AA9D2AB0-20B8-4B04-B111-AE0DC118310F" },
                { "key_ops", new List<string> { "encrypt", "verify" } },
                { "x5u", "https://thetrap.com/main.crt" },
                { "x5t", "5hJMjOCG0aFBwPGVCyAhepsmDwI" },
                { "x5t#S256", "uyIuvRrCqDBYz5XIDMk5z1CT5_Gpel_8GylIAFZxRVc" },
                { "x5c", new List<string>
                    {
                        "MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se",
                        "MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ=="
                    }
                }
            };

            //when
            var test = Jwk.FromDictionary(data);

            //then
            Assert.Equal("OKP", test.Kty);
            Assert.Equal("AA9D2AB0-20B8-4B04-B111-AE0DC118310F", test.KeyId);
            Assert.Equal("PS256", test.Alg);
            Assert.Equal(Jwk.KeyUsage.Signature, test.Use);
            Assert.Equal(2, test.KeyOps.Count);
            Assert.Equal(new[] { Jwk.KeyOperations.Encrypt, Jwk.KeyOperations.Verify }, test.KeyOps);
            Assert.Equal("https://thetrap.com/main.crt", test.X5U);
            Assert.Equal("5hJMjOCG0aFBwPGVCyAhepsmDwI", test.X5T);
            Assert.Equal("uyIuvRrCqDBYz5XIDMk5z1CT5_Gpel_8GylIAFZxRVc", test.X5TSha256);
            Assert.Equal(new List<string>
            {
                "MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se",
                "MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ=="
            }, test.X5C);
            Assert.Null(test.OtherParams);
        }

        [Fact]
        public void FromJson_OtherParams()
        {
            //given
            string json = @"
            {
                ""kty"":""PBKDF2"",
                ""s"":""2WCTcJZ1Rvd_CJuJripQ1w"",
                ""c"":4096
            }";

            //when
            var test = Jwk.FromJson(json, JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal("PBKDF2", test.Kty);
            Assert.Equal(2, test.OtherParams.Count);
            Assert.Equal("2WCTcJZ1Rvd_CJuJripQ1w", test.OtherParams["s"]);
            Assert.Equal(4096, test.OtherParams["c"]);
        }

        [Fact]
        public void FromDictionary_OtherParams()
        {
            //given
            var data = new Dictionary<string, object>
            {
                { "kty", "PBKDF2" },
                { "s", "2WCTcJZ1Rvd_CJuJripQ1w" },
                { "c", 4096 },
            };

            //when
            var test = Jwk.FromDictionary(data);

            //then
            Assert.Equal("PBKDF2", test.Kty);
            Assert.Equal(2, test.OtherParams.Count);
            Assert.Equal("2WCTcJZ1Rvd_CJuJripQ1w", test.OtherParams["s"]);
            Assert.Equal(4096, test.OtherParams["c"]);
        }

        [Fact]
        public void ToDictionary_OtherParams()
        {
            //given
            var key = new Jwk();

            key.Kty = "PBKDF2";
            key.OtherParams = new Dictionary<string, object>();
            key.OtherParams["s"] = "2WCTcJZ1Rvd_CJuJripQ1w";
            key.OtherParams["c"] = 4096;

            //when
            var test = key.ToDictionary();

            //then
            Assert.Equal(3, test.Count);
            Assert.Equal("PBKDF2", test["kty"]);
            Assert.Equal("2WCTcJZ1Rvd_CJuJripQ1w", test["s"]);
            Assert.Equal(4096, test["c"]);
        }

        [Fact]
        public void ToJson_OtherParams()
        {
            //given
            var key = new Jwk();

            key.Kty = "PBKDF2";
            key.OtherParams = new Dictionary<string, object>();
            key.OtherParams["s"] = "2WCTcJZ1Rvd_CJuJripQ1w";
            key.OtherParams["c"] = 4096;

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal(@"{""kty"":""PBKDF2"",""s"":""2WCTcJZ1Rvd_CJuJripQ1w"",""c"":4096}", test);
        }

        [Fact]
        public void ToDictionary_OctKey()
        {
            //given
            var key = new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

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
            var test = Jwk.FromDictionary(data);

            //then
            Assert.Equal(Jwk.KeyTypes.OCT, test.Kty);
            Assert.Equal("GawgguFyGrWKav7AX4VKUg", test.K);
            Assert.Equal(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 }, test.OctKey());
        }

        [Fact]
        public void ToJson_OctKey()
        {
            //given
            var key = new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper);

            //then 
            Console.Out.WriteLine(test);

            Assert.Equal(@"{""kty"":""oct"",""k"":""GawgguFyGrWKav7AX4VKUg""}", test);
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
            var test = Jwk.FromJson(json, JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal(Jwk.KeyTypes.OCT, test.Kty);
            Assert.Equal("GawgguFyGrWKav7AX4VKUg", test.K);
            Assert.Equal(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 }, test.OctKey());
        }

        [Fact]
        public void OctKey()
        {
            //given
            var key = new Jwk(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 });

            //then            
            Assert.Equal(new byte[] { 25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82 }, key.OctKey());
            Assert.Equal("GawgguFyGrWKav7AX4VKUg", key.K);
        }

        [Fact]
        public void ToDictionary_RsaPubKey()
        {
            //given
            var key = new Jwk(
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
            var key = new Jwk(
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
            var test = Jwk.FromDictionary(data);

            //then
            Assert.Equal(Jwk.KeyTypes.RSA, test.Kty);
            Assert.Equal(Jwk.KeyUsage.Signature, test.Use);
            Assert.Equal("AQAB", test.E);
            Assert.Equal("qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q", test.N);
            Assert.Equal("0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts", test.P);
            Assert.Equal("zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s", test.Q);
            Assert.Equal("lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ", test.D);
            Assert.Equal("KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M", test.DP);
            Assert.Equal("Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU", test.DQ);
            Assert.Equal("sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g", test.QI);

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
            var key = new Jwk(
                e: "AQAB",
                n: "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"
            );

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper);

            //then
            Console.Out.WriteLine(test);
            Assert.Equal(@"{""kty"":""RSA"",""e"":""AQAB"",""n"":""qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q""}", test);
        }

        [Fact]
        public void ToJson_PrivateRsaKey()
        {
            //given
            var key = new Jwk(
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
            Assert.Equal(@"{""kty"":""RSA"",""e"":""AQAB"",""n"":""qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q"",""d"":""lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ"",""p"":""0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts"",""q"":""zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s"",""dp"":""KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M"",""dq"":""Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU"",""qi"":""sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g""}", test);
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
            var test = Jwk.FromJson(json, JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal(Jwk.KeyTypes.RSA, test.Kty);
            Assert.Equal("Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc", test.KeyId);
            Assert.Equal("AQAB", test.E);
            Assert.Equal("qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q", test.N);
            Assert.Equal("0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts", test.P);
            Assert.Equal("zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s", test.Q);
            Assert.Equal("lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ", test.D);
            Assert.Equal("KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M", test.DP);
            Assert.Equal("Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU", test.DQ);
            Assert.Equal("sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g", test.QI);

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
            var test = new Jwk(PubRsaKey(), false);

            //then
            Assert.Equal(Jwk.KeyTypes.RSA, test.Kty);
            Assert.Equal("AQAB", test.E);
            Assert.Equal("qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q", test.N);
        }

        [Fact]
        public void NewRsaPrivKey()
        {
            //given
            var test = new Jwk(PrivRsaKey());

            //then
            Assert.Equal(Jwk.KeyTypes.RSA, test.Kty);
            Assert.Equal("AQAB", test.E);
            Assert.Equal("qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q", test.N);
            Assert.Equal("lJhwb0pKlB2ivyDFO6thajotClrMA3nxIiSkIUbvVr-TToFtha36gyF6w6e6YNXQXs4HhMRy1_b-nRQDk8G4_f5urd_q-pOn5u4KfmqN3Xw-lYD3ddi9qF0NLeTVUNVFASeP0FFqbPYfdNwD-LyvwjhtT_ggMOAw3mYvU5cBfz6-3uPdhl3CwQFCTgwOud_BA9p2MPMUHG82wMK_sNO1I0TYpjm7TnwNBwiKbMf-i5CKnuohgoYrEDYLeMg3f32eBljlCFNYaoCtT-mr1Ze0OTJND04vbfLotV-BBKulIpbOOSeVpKG7gJxZHmv7in7PE5_WzaxKFVoHW3wR6v_GzQ", test.D);
            Assert.Equal("0qaOkT174vRG3E_67gU3lgOgoT6L3pVHuu7wfrIEoxycPa5_mZVG54SgvQUofGUYEGjR0lavUAjClw9tOzcODHX8RAxkuDntAFntBxgRM-IzAy8QzeRl_cbhgVjBTAhBcxg-3VySv5GdxFyrQaIo8Oy_PPI1L4EFKZHmicBd3ts", test.P);
            Assert.Equal("KTWmTGmf092AA1euOmRQ5IsfIIxQ5qGDn-FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz-50xIDbs4_j5pWx1BJVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW-_Iw4gKWNptxZ6T1lBD8UWHaPiEFW2-M", test.DP);
            Assert.Equal("zJPqCDKqaJH9TAGfzt6b4aNt9fpirEcdpAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODERCtPqjECXXsxH-az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOpYI5_UfYnw1s", test.Q);
            Assert.Equal("Jn0lqMkvemENEMG1eUw0c601wPOMoPD4SKTlnKWPTlQS6YISbNF5UKSuFLwoJa9HA8BifDrD-Mfpo1M1HPmnoilEWUrfwMqqdCkOlbiJQhKY8AZ16QGH50kDXhmVVa8BRWdVQWBTUzWXS5kXMaeskVzextTgymPcOAhXN-ph7MU", test.DQ);
            Assert.Equal("sRAPigJpl8S_vsf1zhJTrHM97xRwuB26R6Tm-J8sKRPb7p5xxNlmOBBFvWmWxdto8dBElNlydSZan373yBLxzW-bZgVp-B2RKT1B3WhTYW_Vo5DLhWi84XMncJxH7avtxtF9yksaeKe0e2n3J6TTan53mDg4KF8U0OEO2ciqO9g", test.QI);
        }

        [Fact]
        public void RsaKey_Public()
        {
            //given
            var key = new Jwk("AQAB", "qFZv0pea_jn5Mo4qEUmStuhlulso8n1inXbEotd_zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO_0N97dMBz_7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7-GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8_mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu_ve0v7LiLT4G_OxYGzpOQcCnimKdojzNP6GtVDaMPh-QkSJE32UCos9R3wI2Q");

            //when
            var test = key.RsaKey();

            RSAParameters p = test.ExportParameters(false);

            //then
            Assert.Equal(new byte[] { 1, 0, 1 }, p.Exponent);
            Assert.Equal(new byte[] { 168, 86, 111, 210, 151, 154, 254, 57, 249, 50, 142, 42, 17, 73, 146, 182, 232, 101, 186, 91, 40, 242, 125, 98, 157, 118, 196, 162, 215, 127, 205, 58, 208, 167, 210, 180, 68, 173, 33, 127, 187, 116, 43, 128, 99, 41, 88, 90, 138, 162, 26, 155, 139, 85, 85, 11, 228, 153, 135, 129, 121, 138, 245, 50, 105, 206, 255, 67, 125, 237, 211, 1, 207, 254, 223, 154, 252, 175, 210, 24, 7, 104, 23, 80, 230, 100, 121, 187, 114, 211, 148, 122, 60, 182, 52, 68, 239, 225, 179, 102, 97, 172, 234, 51, 28, 202, 62, 199, 109, 122, 27, 12, 244, 9, 102, 154, 141, 203, 162, 99, 150, 32, 213, 95, 21, 188, 157, 98, 67, 122, 220, 70, 6, 90, 166, 78, 61, 68, 213, 250, 246, 68, 43, 25, 46, 183, 131, 56, 244, 131, 33, 231, 70, 214, 234, 115, 245, 26, 218, 74, 27, 8, 15, 55, 158, 124, 231, 10, 137, 183, 0, 104, 167, 158, 84, 141, 235, 144, 5, 60, 254, 99, 154, 184, 180, 151, 191, 126, 225, 150, 77, 33, 234, 196, 173, 37, 189, 234, 101, 5, 242, 57, 73, 21, 146, 53, 200, 146, 27, 205, 187, 251, 222, 210, 254, 203, 136, 180, 248, 27, 243, 177, 96, 108, 233, 57, 7, 2, 158, 41, 138, 118, 136, 243, 52, 254, 134, 181, 80, 218, 48, 248, 126, 66, 68, 137, 19, 125, 148, 10, 139, 61, 71, 124, 8, 217 }, p.Modulus);
        }

        [Fact]
        public void RsaKey_Private()
        {
            //given
            var key = new Jwk(
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
            Assert.Equal(new byte[] { 1, 0, 1 }, p.Exponent);
            Assert.Equal(new byte[] { 168, 86, 111, 210, 151, 154, 254, 57, 249, 50, 142, 42, 17, 73, 146, 182, 232, 101, 186, 91, 40, 242, 125, 98, 157, 118, 196, 162, 215, 127, 205, 58, 208, 167, 210, 180, 68, 173, 33, 127, 187, 116, 43, 128, 99, 41, 88, 90, 138, 162, 26, 155, 139, 85, 85, 11, 228, 153, 135, 129, 121, 138, 245, 50, 105, 206, 255, 67, 125, 237, 211, 1, 207, 254, 223, 154, 252, 175, 210, 24, 7, 104, 23, 80, 230, 100, 121, 187, 114, 211, 148, 122, 60, 182, 52, 68, 239, 225, 179, 102, 97, 172, 234, 51, 28, 202, 62, 199, 109, 122, 27, 12, 244, 9, 102, 154, 141, 203, 162, 99, 150, 32, 213, 95, 21, 188, 157, 98, 67, 122, 220, 70, 6, 90, 166, 78, 61, 68, 213, 250, 246, 68, 43, 25, 46, 183, 131, 56, 244, 131, 33, 231, 70, 214, 234, 115, 245, 26, 218, 74, 27, 8, 15, 55, 158, 124, 231, 10, 137, 183, 0, 104, 167, 158, 84, 141, 235, 144, 5, 60, 254, 99, 154, 184, 180, 151, 191, 126, 225, 150, 77, 33, 234, 196, 173, 37, 189, 234, 101, 5, 242, 57, 73, 21, 146, 53, 200, 146, 27, 205, 187, 251, 222, 210, 254, 203, 136, 180, 248, 27, 243, 177, 96, 108, 233, 57, 7, 2, 158, 41, 138, 118, 136, 243, 52, 254, 134, 181, 80, 218, 48, 248, 126, 66, 68, 137, 19, 125, 148, 10, 139, 61, 71, 124, 8, 217 }, p.Modulus);
            Assert.Equal(new byte[] { 148, 152, 112, 111, 74, 74, 148, 29, 162, 191, 32, 197, 59, 171, 97, 106, 58, 45, 10, 90, 204, 3, 121, 241, 34, 36, 164, 33, 70, 239, 86, 191, 147, 78, 129, 109, 133, 173, 250, 131, 33, 122, 195, 167, 186, 96, 213, 208, 94, 206, 7, 132, 196, 114, 215, 246, 254, 157, 20, 3, 147, 193, 184, 253, 254, 110, 173, 223, 234, 250, 147, 167, 230, 238, 10, 126, 106, 141, 221, 124, 62, 149, 128, 247, 117, 216, 189, 168, 93, 13, 45, 228, 213, 80, 213, 69, 1, 39, 143, 208, 81, 106, 108, 246, 31, 116, 220, 3, 248, 188, 175, 194, 56, 109, 79, 248, 32, 48, 224, 48, 222, 102, 47, 83, 151, 1, 127, 62, 190, 222, 227, 221, 134, 93, 194, 193, 1, 66, 78, 12, 14, 185, 223, 193, 3, 218, 118, 48, 243, 20, 28, 111, 54, 192, 194, 191, 176, 211, 181, 35, 68, 216, 166, 57, 187, 78, 124, 13, 7, 8, 138, 108, 199, 254, 139, 144, 138, 158, 234, 33, 130, 134, 43, 16, 54, 11, 120, 200, 55, 127, 125, 158, 6, 88, 229, 8, 83, 88, 106, 128, 173, 79, 233, 171, 213, 151, 180, 57, 50, 77, 15, 78, 47, 109, 242, 232, 181, 95, 129, 4, 171, 165, 34, 150, 206, 57, 39, 149, 164, 161, 187, 128, 156, 89, 30, 107, 251, 138, 126, 207, 19, 159, 214, 205, 172, 74, 21, 90, 7, 91, 124, 17, 234, 255, 198, 205 }, p.D);
            Assert.Equal(new byte[] { 210, 166, 142, 145, 61, 123, 226, 244, 70, 220, 79, 250, 238, 5, 55, 150, 3, 160, 161, 62, 139, 222, 149, 71, 186, 238, 240, 126, 178, 4, 163, 28, 156, 61, 174, 127, 153, 149, 70, 231, 132, 160, 189, 5, 40, 124, 101, 24, 16, 104, 209, 210, 86, 175, 80, 8, 194, 151, 15, 109, 59, 55, 14, 12, 117, 252, 68, 12, 100, 184, 57, 237, 0, 89, 237, 7, 24, 17, 51, 226, 51, 3, 47, 16, 205, 228, 101, 253, 198, 225, 129, 88, 193, 76, 8, 65, 115, 24, 62, 221, 92, 146, 191, 145, 157, 196, 92, 171, 65, 162, 40, 240, 236, 191, 60, 242, 53, 47, 129, 5, 41, 145, 230, 137, 192, 93, 222, 219 }, p.P);
            Assert.Equal(new byte[] { 204, 147, 234, 8, 50, 170, 104, 145, 253, 76, 1, 159, 206, 222, 155, 225, 163, 109, 245, 250, 98, 172, 71, 29, 164, 1, 117, 108, 39, 157, 21, 244, 38, 81, 147, 52, 44, 109, 235, 50, 211, 128, 34, 24, 196, 94, 0, 3, 183, 145, 129, 241, 147, 74, 220, 20, 37, 240, 18, 114, 50, 98, 172, 231, 186, 10, 153, 181, 92, 56, 49, 17, 10, 211, 234, 140, 64, 151, 94, 204, 71, 249, 172, 253, 159, 60, 90, 180, 251, 220, 111, 184, 166, 21, 111, 14, 149, 107, 37, 194, 190, 8, 33, 18, 157, 18, 60, 196, 98, 206, 44, 201, 2, 115, 238, 77, 164, 182, 163, 169, 96, 142, 127, 81, 246, 39, 195, 91 }, p.Q);
            Assert.Equal(new byte[] { 177, 16, 15, 138, 2, 105, 151, 196, 191, 190, 199, 245, 206, 18, 83, 172, 115, 61, 239, 20, 112, 184, 29, 186, 71, 164, 230, 248, 159, 44, 41, 19, 219, 238, 158, 113, 196, 217, 102, 56, 16, 69, 189, 105, 150, 197, 219, 104, 241, 208, 68, 148, 217, 114, 117, 38, 90, 159, 126, 247, 200, 18, 241, 205, 111, 155, 102, 5, 105, 248, 29, 145, 41, 61, 65, 221, 104, 83, 97, 111, 213, 163, 144, 203, 133, 104, 188, 225, 115, 39, 112, 156, 71, 237, 171, 237, 198, 209, 125, 202, 75, 26, 120, 167, 180, 123, 105, 247, 39, 164, 211, 106, 126, 119, 152, 56, 56, 40, 95, 20, 208, 225, 14, 217, 200, 170, 59, 216 }, p.InverseQ);
            Assert.Equal(new byte[] { 41, 53, 166, 76, 105, 159, 211, 221, 128, 3, 87, 174, 58, 100, 80, 228, 139, 31, 32, 140, 80, 230, 161, 131, 159, 225, 96, 177, 24, 120, 105, 196, 142, 24, 79, 11, 237, 106, 211, 173, 53, 56, 16, 226, 114, 114, 43, 128, 210, 172, 254, 231, 76, 72, 13, 187, 56, 254, 62, 105, 91, 29, 65, 37, 84, 235, 158, 16, 98, 159, 219, 205, 46, 181, 104, 246, 107, 81, 234, 57, 133, 75, 73, 40, 219, 110, 164, 57, 74, 112, 17, 82, 224, 181, 212, 35, 161, 181, 139, 142, 216, 174, 104, 197, 190, 252, 140, 56, 128, 165, 141, 166, 220, 89, 233, 61, 101, 4, 63, 20, 88, 118, 143, 136, 65, 86, 219, 227 }, p.DP);
            Assert.Equal(new byte[] { 38, 125, 37, 168, 201, 47, 122, 97, 13, 16, 193, 181, 121, 76, 52, 115, 173, 53, 192, 243, 140, 160, 240, 248, 72, 164, 229, 156, 165, 143, 78, 84, 18, 233, 130, 18, 108, 209, 121, 80, 164, 174, 20, 188, 40, 37, 175, 71, 3, 192, 98, 124, 58, 195, 248, 199, 233, 163, 83, 53, 28, 249, 167, 162, 41, 68, 89, 74, 223, 192, 202, 170, 116, 41, 14, 149, 184, 137, 66, 18, 152, 240, 6, 117, 233, 1, 135, 231, 73, 3, 94, 25, 149, 85, 175, 1, 69, 103, 85, 65, 96, 83, 83, 53, 151, 75, 153, 23, 49, 167, 172, 145, 92, 222, 198, 212, 224, 202, 99, 220, 56, 8, 87, 55, 234, 97, 236, 197 }, p.DQ);
        }

        [Fact]
        public void EccKey_Cng_Public()
        {
            //given
            var key = new Jwk(crv: "P-256", x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU");

            //when
            var test = key.CngKey();

            //then
            Assert.NotNull(test);
            Assert.Equal("P-256", key.Crv);
            Assert.Equal(CngAlgorithm.ECDsaP256, test.Algorithm);
            Assert.True(test.IsEphemeral);
        }

        [Fact]
        public void EccKey_Cng_Private()
        {
            //given
            var key = new Jwk(crv: "P-256",
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
                              d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
                           );

            //when
            var test = key.CngKey();

            //then
            Assert.NotNull(test);
            Assert.Equal("P-256", key.Crv);
            Assert.Equal(CngAlgorithm.ECDsaP256, test.Algorithm);
            Assert.True(test.IsEphemeral);
        }

        [Fact]
        public void EccKey_Cng_Private_KeyAgreement()
        {
            //given
            var key = new Jwk(crv: "P-256",
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
                              d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
                           );

            //when
            var test = key.CngKey(CngKeyUsages.KeyAgreement);

            //then
            Assert.NotNull(test);
            Assert.Equal("P-256", key.Crv);
            Assert.Equal(CngAlgorithm.ECDiffieHellmanP256, test.Algorithm);
            Assert.True(test.IsEphemeral);
        }

#if NETSTANDARD || NET472
        [Fact]
        public void EccKey_ECDsa_Public_P256()
        {
            //given
            var key = new Jwk(crv: "P-256", x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU");

            //when
            var test = key.ECDsaKey();

            //then
            Assert.NotNull(test);
            Assert.Equal("P-256", key.Crv);
            Assert.Equal(256, test.KeySize);

            // Make sure no private key
            Assert.Throws<CryptographicException>(() => test.ExportParameters(true));
        }

        [Fact]
        public void EccKey_ECDsa_Private_P256()
        {
            //given
            var key = new Jwk(crv: "P-256",
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
                              d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
                           );

            //when
            var test = key.ECDsaKey();

            //then
            Assert.NotNull(test);
            Assert.Equal("P-256", key.Crv);
            Assert.Equal(256, test.KeySize);

            Assert.NotNull(test.ExportParameters(true).D);
        }

        [Fact]
        public void EccKey_ECDsa_Public_P384()
        {
            //given
            var key = new Jwk(crv: "P-384", 
                x: "Rpfcsz4AT-hyQDpLW9HogAeJlyoNlA-FXdcHA4h8DmXyz8BF1JFYO94hfy4e2q9P", 
                y: "vcrEHpk1FnqrBLwqRwIJwb8Rb7ROBm6Z8JPLLZjstZzo3-OURJTdsDmVLMtTVUs3");

            //when
            var test = key.ECDsaKey();

            //then
            Assert.NotNull(test);
            Assert.Equal("P-384", key.Crv);
            Assert.Equal(384, test.KeySize);

            // Make sure no private key
            Assert.Throws<CryptographicException>(() => test.ExportParameters(true));
        }

        [Fact]
        public void EccKey_ECDsa_Private_P384()
        {
            //given
            var key = new Jwk(crv: "P-384",
                x: "Rpfcsz4AT-hyQDpLW9HogAeJlyoNlA-FXdcHA4h8DmXyz8BF1JFYO94hfy4e2q9P",
                y: "vcrEHpk1FnqrBLwqRwIJwb8Rb7ROBm6Z8JPLLZjstZzo3-OURJTdsDmVLMtTVUs3",
                d: "ice3abxagFJ0L6Fk3WHQQK33CSq6vbVuGOH-iEuc8tFe2joOIb4PUo3uz9afjPeL"
            );

            //when
            var test = key.ECDsaKey();

            //then
            Assert.NotNull(test);
            Assert.Equal("P-384", key.Crv);
            Assert.Equal(384, test.KeySize);

            Assert.NotNull(test.ExportParameters(true).D);
        }

        [Fact]
        public void EccKey_ECDsa_Public_P521()
        {
            //given
            var key = new Jwk(crv: "P-521",
                x: "APhJyzW4IkVv2eb_bNTx5V_vXYNkJVaYV2KqKxkjUIk-cMVxinRyN6WACIuU7W15KM0DPX8cwzor5ODkUuDblMxg",
                y: "ADxHYXBqI3lQthSnjwj2bOqgwQoDlC0LOrG-rBqyvPBbGUNPQPHLQd_aDONSskKgE8LZrD36F07agqBp2NDrfC4g");

            //when
            var test = key.ECDsaKey();

            //then
            Assert.NotNull(test);
            Assert.Equal("P-521", key.Crv);
            Assert.Equal(521, test.KeySize);

            // Make sure no private key
            Assert.Throws<CryptographicException>(() => test.ExportParameters(true));
        }

        [Fact]
        public void EccKey_ECDsa_Private_P521()
        {
            //given
            var key = new Jwk(crv: "P-521",
                x: "APhJyzW4IkVv2eb_bNTx5V_vXYNkJVaYV2KqKxkjUIk-cMVxinRyN6WACIuU7W15KM0DPX8cwzor5ODkUuDblMxg",
                y: "ADxHYXBqI3lQthSnjwj2bOqgwQoDlC0LOrG-rBqyvPBbGUNPQPHLQd_aDONSskKgE8LZrD36F07agqBp2NDrfC4g",
                d: "AN6BCYXPe3SwU1-pHXmgiRYVsDvLgT5vE04OrhTTOKBTKkrb0CfnIVRyR2ptoXTzppL854nkY5WYe8mdm4O1arNw"
            );

            //when
            var test = key.ECDsaKey();

            //then
            Assert.NotNull(test);
            Assert.Equal("P-521", key.Crv);
            Assert.Equal(521, test.KeySize);

            Assert.NotNull(test.ExportParameters(true).D);
        }

        [Fact]
        public void NewECDsa_Public_P256()
        {
            //given
            var test = new Jwk(ECDSa256Public(), false);

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-256", test.Crv);
            Assert.Equal("BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", test.X);
            Assert.Equal("g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU", test.Y);
            Assert.Null(test.D);
        }

        [Fact]
        public void NewECDsa_Private_P256()
        {
            //given
            var test = new Jwk(ECDSa256Private());

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-256", test.Crv);
            Assert.Equal("BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", test.X);
            Assert.Equal("g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU", test.Y);
            Assert.Equal("KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4", test.D);
        }

        [Fact]
        public void NewECDsa_Public_P384()
        {
            //given
            var test = new Jwk(ECDSa384Public(), false);

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-384", test.Crv);
            Assert.Equal("Rpfcsz4AT-hyQDpLW9HogAeJlyoNlA-FXdcHA4h8DmXyz8BF1JFYO94hfy4e2q9P", test.X);
            Assert.Equal("vcrEHpk1FnqrBLwqRwIJwb8Rb7ROBm6Z8JPLLZjstZzo3-OURJTdsDmVLMtTVUs3", test.Y);
            Assert.Null(test.D);
        }

        [Fact]
        public void NewECDsa_Private_P384()
        {
            //given
            var test = new Jwk(ECDSa384Private());

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-384", test.Crv);
            Assert.Equal("Rpfcsz4AT-hyQDpLW9HogAeJlyoNlA-FXdcHA4h8DmXyz8BF1JFYO94hfy4e2q9P", test.X);
            Assert.Equal("vcrEHpk1FnqrBLwqRwIJwb8Rb7ROBm6Z8JPLLZjstZzo3-OURJTdsDmVLMtTVUs3", test.Y);
            Assert.Equal("ice3abxagFJ0L6Fk3WHQQK33CSq6vbVuGOH-iEuc8tFe2joOIb4PUo3uz9afjPeL", test.D);
        }

        [Fact]
        public void NewECDsa_Public_P521()
        {
            //given
            var test = new Jwk(ECDSa521Public(), false);

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-521", test.Crv);
            Assert.Equal("APhJyzW4IkVv2eb_bNTx5V_vXYNkJVaYV2KqKxkjUIk-cMVxinRyN6WACIuU7W15KM0DPX8cwzor5ODkUuDblMxg", test.X);
            Assert.Equal("ADxHYXBqI3lQthSnjwj2bOqgwQoDlC0LOrG-rBqyvPBbGUNPQPHLQd_aDONSskKgE8LZrD36F07agqBp2NDrfC4g", test.Y);
            Assert.Null(test.D);
        }

        [Fact]
        public void NewECDsa_Private_P521()
        {
            //given
            var test = new Jwk(ECDSa521Private());

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-521", test.Crv);
            Assert.Equal("APhJyzW4IkVv2eb_bNTx5V_vXYNkJVaYV2KqKxkjUIk-cMVxinRyN6WACIuU7W15KM0DPX8cwzor5ODkUuDblMxg", test.X);
            Assert.Equal("ADxHYXBqI3lQthSnjwj2bOqgwQoDlC0LOrG-rBqyvPBbGUNPQPHLQd_aDONSskKgE8LZrD36F07agqBp2NDrfC4g", test.Y);
            Assert.Equal("AN6BCYXPe3SwU1-pHXmgiRYVsDvLgT5vE04OrhTTOKBTKkrb0CfnIVRyR2ptoXTzppL854nkY5WYe8mdm4O1arNw", test.D);
        }

#endif

        [Fact]
        public void NewEccCng_Public_P256()
        {
            //given
            var test = new Jwk(Ecc256Public(), false);

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-256", test.Crv);
            Assert.Equal("BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", test.X);
            Assert.Equal("g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU", test.Y);
            Assert.Null(test.D);
        }

        [Fact]
        public void NewEccCng_Private_P256()
        {
            //given
            var test = new Jwk(Ecc256Private());

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-256", test.Crv);
            Assert.Equal("BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", test.X);
            Assert.Equal("g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU", test.Y);
            Assert.Equal("KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4", test.D);
        }

        [Fact]
        public void NewEccCng_Public_P384()
        {
            //given
            var test = new Jwk(Ecc384Public(), false);

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-384", test.Crv);
            Assert.Equal("Rpfcsz4AT-hyQDpLW9HogAeJlyoNlA-FXdcHA4h8DmXyz8BF1JFYO94hfy4e2q9P", test.X);
            Assert.Equal("vcrEHpk1FnqrBLwqRwIJwb8Rb7ROBm6Z8JPLLZjstZzo3-OURJTdsDmVLMtTVUs3", test.Y);
            Assert.Null(test.D);
        }

        [Fact]
        public void NewEccCng_Private_P384()
        {
            //given
            var test = new Jwk(Ecc384Private());

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-384", test.Crv);
            Assert.Equal("Rpfcsz4AT-hyQDpLW9HogAeJlyoNlA-FXdcHA4h8DmXyz8BF1JFYO94hfy4e2q9P", test.X);
            Assert.Equal("vcrEHpk1FnqrBLwqRwIJwb8Rb7ROBm6Z8JPLLZjstZzo3-OURJTdsDmVLMtTVUs3", test.Y);
            Assert.Equal("ice3abxagFJ0L6Fk3WHQQK33CSq6vbVuGOH-iEuc8tFe2joOIb4PUo3uz9afjPeL", test.D);
        }
        [Fact]

        public void NewEccCng_Public_P521()
        {
            //given
            var test = new Jwk(Ecc512Public(), false);

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-521", test.Crv);
            Assert.Equal("APhJyzW4IkVv2eb_bNTx5V_vXYNkJVaYV2KqKxkjUIk-cMVxinRyN6WACIuU7W15KM0DPX8cwzor5ODkUuDblMxg", test.X);
            Assert.Equal("ADxHYXBqI3lQthSnjwj2bOqgwQoDlC0LOrG-rBqyvPBbGUNPQPHLQd_aDONSskKgE8LZrD36F07agqBp2NDrfC4g", test.Y);
            Assert.Null(test.D);
        }

        [Fact]
        public void NewEccCng_Private_P521()
        {
            //given
            var test = new Jwk(Ecc512Private());

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal("P-521", test.Crv);
            Assert.Equal("APhJyzW4IkVv2eb_bNTx5V_vXYNkJVaYV2KqKxkjUIk-cMVxinRyN6WACIuU7W15KM0DPX8cwzor5ODkUuDblMxg", test.X);
            Assert.Equal("ADxHYXBqI3lQthSnjwj2bOqgwQoDlC0LOrG-rBqyvPBbGUNPQPHLQd_aDONSskKgE8LZrD36F07agqBp2NDrfC4g", test.Y);
            Assert.Equal("AN6BCYXPe3SwU1-pHXmgiRYVsDvLgT5vE04OrhTTOKBTKkrb0CfnIVRyR2ptoXTzppL854nkY5WYe8mdm4O1arNw", test.D);
        }

        [Fact]
        public void ToDictionary_EccPubKey()
        {
            //given
            var key = new Jwk(crv: "P-256",
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
            var key = new Jwk(crv: "P-256",
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
            var test = Jwk.FromDictionary(data);

            //then
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal(Jwk.KeyUsage.Encryption, test.Use);
            Assert.Equal("P-256", test.Crv);
            Assert.Equal("BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", test.X);
            Assert.Equal("g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU", test.Y);
            Assert.Equal("KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4", test.D);

            var key = test.CngKey();

            Assert.NotNull(key);
            Assert.Equal(CngAlgorithm.ECDsaP256, key.Algorithm);
            Assert.True(key.IsEphemeral);
        }

        [Fact]
        public void ToJson_EccPubKey()
        {
            //given
            var key = new Jwk(crv: "P-256",
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU"
                           );

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper);

            //then
            Console.Out.WriteLine(test);
            Assert.Equal(@"{""kty"":""EC"",""crv"":""P-256"",""x"":""BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk"",""y"":""g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU""}", test);
        }

        [Fact]
        public void ToJson_EccPrivKey()
        {
            //given
            var key = new Jwk(crv: "P-256",
                              x: "BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk",
                              y: "g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU",
                              d: "KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"
                           );

            //when
            var test = key.ToJson(JWT.DefaultSettings.JsonMapper);

            //then
            Console.Out.WriteLine(test);
            Assert.Equal(@"{""kty"":""EC"",""crv"":""P-256"",""x"":""BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk"",""y"":""g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU"",""d"":""KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4""}", test);
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
            var test = Jwk.FromJson(json, JWT.DefaultSettings.JsonMapper);

            //then
            Assert.Equal("Ex-p1KJFz8hQE1S76SzkhHcaObCKoDPrtAPJdWuTcTc", test.KeyId);
            Assert.Equal(Jwk.KeyTypes.EC, test.Kty);
            Assert.Equal(Jwk.KeyUsage.Encryption, test.Use);
            Assert.Equal("P-256", test.Crv);
            Assert.Equal("BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk", test.X);
            Assert.Equal("g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU", test.Y);
            Assert.Equal("KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4", test.D);

            var key = test.CngKey();

            Assert.NotNull(key);

            Assert.NotNull(key);
            Assert.Equal(CngAlgorithm.ECDsaP256, key.Algorithm);
            Assert.True(key.IsEphemeral);
        }

        [Fact]
        public void AddX509()
        {
            //given
            var jwk = new Jwk();

            var chain = X509Chain();

            //when
            // let's add one

            jwk.Add(chain[0]);

            Assert.Equal(new List<string>
            {
                "MIIEoDCCAogCCQDU5pKjdLHJvzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MDU0OVoXDTMxMTIxNzE3MDU0OVowEjEQMA4GA1UEAwwHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBiqzJ6O7wLuFE42569qU3pR5CklXWE2XuNnt3LNglYOAOTy8j5xiImiIj+xN4K9qvPu30xbDL1EV83fom5zY2145RFvDc/FKKjmp1RrmL6rErRW2VbppuxSLXgNYUu6cffLbANCJdOmTPkAEwB+8GqnsEou00NFSM6LTJIihfpVln3mOr+wn9bQr7LQ62zdkj0i+rgxojyNhNNWVuGuRNV4kQRPhXMedUbKz73XoGOt3EXsyed81oMfkLZ0mh3Z3hAq0upUaCD6NeydVOTY62RgnUop7EdN+wruW3GRLReRq0ZtRFWNiaNfQA5ffSggzdtk7DDc6IU5vZDc/GZZP2VEZRzQ9HHw6Z6UfeRlL2H1YctGEEDIWX1sUYpHK1zzZtcOjbGsKpJtMuPFkVwJs9QOFEHtncxJaNN73e70/yv65PvuPhuFmKExVqEfu37IxM2Qoilii8/WBK9RonLe0qTLqNH2suXFkBDp9vhhUHGeho+m9ExhDQHpbRiXMw3EZDMICkvujhAqlK8wqcOfN0+urf8tzO9LtwX8czKbUq0R4HuGGdexd06/rK8GuUAr6aDSNdGkREeGl8EceYmBuGTmYRs/SqRRpW+k5O05gK7Nbvo2rU3BKL8y13AF95a5yXIZ3mJarXciv/WCv5sITcUtDIwZa/AkpaIGROQF2ejAgMBAAEwDQYJKoZIhvcNAQELBQADggIBACwqqfzL/irX7xpepIg7sydaC1CpYp86bC+UiG4C7QdKuuDrguY37n38kg5D5x6nOBIAjqgW45hUUcSJBVItS8nLtGrtopnyWJfr/bbfVT7MXMpJKEaDzPYgkAx12ObDMav6O9m+aj9n3zzGyNKDzmwkEk4IVHR1La0FfleTQ57d/gCjxDjgHLa7ayaXUYIyloPg+OdkMTkOTzMiFfVP3dCuXY7YHmNz2WuL8lPAhvVaEAYW4IPN0BZkseHjfxDKxPaAQrOMPSSYn826Y3XTyUGkBqFYu60VvwVawVhN4bn5oCkbfLHg8+wCCzbCrcrTwAC/cZubwO3/Ko3lzO+hxJDkbcHUgm8xYZziztIAxNGHORHF/6zgi6yvwOQfPNSWs4qWOFSBV3+JNRn+lvRRknRdGs0WPGZN9zIV4rRAuz1H+oh1WSfPdfDwf+qPeHME3sN0uUvNysdQPSnhi8crVv1hT1F+fv420olGKy0pnobvOCmw6uaBNInOm+xDHIsDt36t1P9OC3V9QPd4gs8BHRfssHOcTnptY/3cEwhTzW83QsbFgb9aQn/wDve6kKE9+i9Nd3XUeEIQ9E0MM2oI7vLyLDVg/YqBmxwEpfe6k8l4UI1UZlfn9TSBXhcaQ7VPNNeYS0j5lCEBP06LSV0Lx9YF4ad+sXdI0jAflBQodo6r"
            }, jwk.X5C);

            //when 
            //add two more

            jwk.Add(chain[1]);
            jwk.Add(chain[2]);

            //then we got all three
            Assert.Equal(new List<string>
            {
                "MIIEoDCCAogCCQDU5pKjdLHJvzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MDU0OVoXDTMxMTIxNzE3MDU0OVowEjEQMA4GA1UEAwwHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBiqzJ6O7wLuFE42569qU3pR5CklXWE2XuNnt3LNglYOAOTy8j5xiImiIj+xN4K9qvPu30xbDL1EV83fom5zY2145RFvDc/FKKjmp1RrmL6rErRW2VbppuxSLXgNYUu6cffLbANCJdOmTPkAEwB+8GqnsEou00NFSM6LTJIihfpVln3mOr+wn9bQr7LQ62zdkj0i+rgxojyNhNNWVuGuRNV4kQRPhXMedUbKz73XoGOt3EXsyed81oMfkLZ0mh3Z3hAq0upUaCD6NeydVOTY62RgnUop7EdN+wruW3GRLReRq0ZtRFWNiaNfQA5ffSggzdtk7DDc6IU5vZDc/GZZP2VEZRzQ9HHw6Z6UfeRlL2H1YctGEEDIWX1sUYpHK1zzZtcOjbGsKpJtMuPFkVwJs9QOFEHtncxJaNN73e70/yv65PvuPhuFmKExVqEfu37IxM2Qoilii8/WBK9RonLe0qTLqNH2suXFkBDp9vhhUHGeho+m9ExhDQHpbRiXMw3EZDMICkvujhAqlK8wqcOfN0+urf8tzO9LtwX8czKbUq0R4HuGGdexd06/rK8GuUAr6aDSNdGkREeGl8EceYmBuGTmYRs/SqRRpW+k5O05gK7Nbvo2rU3BKL8y13AF95a5yXIZ3mJarXciv/WCv5sITcUtDIwZa/AkpaIGROQF2ejAgMBAAEwDQYJKoZIhvcNAQELBQADggIBACwqqfzL/irX7xpepIg7sydaC1CpYp86bC+UiG4C7QdKuuDrguY37n38kg5D5x6nOBIAjqgW45hUUcSJBVItS8nLtGrtopnyWJfr/bbfVT7MXMpJKEaDzPYgkAx12ObDMav6O9m+aj9n3zzGyNKDzmwkEk4IVHR1La0FfleTQ57d/gCjxDjgHLa7ayaXUYIyloPg+OdkMTkOTzMiFfVP3dCuXY7YHmNz2WuL8lPAhvVaEAYW4IPN0BZkseHjfxDKxPaAQrOMPSSYn826Y3XTyUGkBqFYu60VvwVawVhN4bn5oCkbfLHg8+wCCzbCrcrTwAC/cZubwO3/Ko3lzO+hxJDkbcHUgm8xYZziztIAxNGHORHF/6zgi6yvwOQfPNSWs4qWOFSBV3+JNRn+lvRRknRdGs0WPGZN9zIV4rRAuz1H+oh1WSfPdfDwf+qPeHME3sN0uUvNysdQPSnhi8crVv1hT1F+fv420olGKy0pnobvOCmw6uaBNInOm+xDHIsDt36t1P9OC3V9QPd4gs8BHRfssHOcTnptY/3cEwhTzW83QsbFgb9aQn/wDve6kKE9+i9Nd3XUeEIQ9E0MM2oI7vLyLDVg/YqBmxwEpfe6k8l4UI1UZlfn9TSBXhcaQ7VPNNeYS0j5lCEBP06LSV0Lx9YF4ad+sXdI0jAflBQodo6r",
                "MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ==",
                "MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se"
            }, jwk.X5C);

            Assert.Equal(chain, jwk.GetX509Chain());
        }

        [Fact]
        public void SetX509Chain()
        {
            //given
            var jwk = new Jwk();
            var chain = X509Chain();

            // let's make sure we not appending here
            jwk.Add(chain[0]);

            //when
            jwk.SetX509Chain(chain);

            //then
            Assert.Equal(new List<string>
            {
                "MIIEoDCCAogCCQDU5pKjdLHJvzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MDU0OVoXDTMxMTIxNzE3MDU0OVowEjEQMA4GA1UEAwwHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBiqzJ6O7wLuFE42569qU3pR5CklXWE2XuNnt3LNglYOAOTy8j5xiImiIj+xN4K9qvPu30xbDL1EV83fom5zY2145RFvDc/FKKjmp1RrmL6rErRW2VbppuxSLXgNYUu6cffLbANCJdOmTPkAEwB+8GqnsEou00NFSM6LTJIihfpVln3mOr+wn9bQr7LQ62zdkj0i+rgxojyNhNNWVuGuRNV4kQRPhXMedUbKz73XoGOt3EXsyed81oMfkLZ0mh3Z3hAq0upUaCD6NeydVOTY62RgnUop7EdN+wruW3GRLReRq0ZtRFWNiaNfQA5ffSggzdtk7DDc6IU5vZDc/GZZP2VEZRzQ9HHw6Z6UfeRlL2H1YctGEEDIWX1sUYpHK1zzZtcOjbGsKpJtMuPFkVwJs9QOFEHtncxJaNN73e70/yv65PvuPhuFmKExVqEfu37IxM2Qoilii8/WBK9RonLe0qTLqNH2suXFkBDp9vhhUHGeho+m9ExhDQHpbRiXMw3EZDMICkvujhAqlK8wqcOfN0+urf8tzO9LtwX8czKbUq0R4HuGGdexd06/rK8GuUAr6aDSNdGkREeGl8EceYmBuGTmYRs/SqRRpW+k5O05gK7Nbvo2rU3BKL8y13AF95a5yXIZ3mJarXciv/WCv5sITcUtDIwZa/AkpaIGROQF2ejAgMBAAEwDQYJKoZIhvcNAQELBQADggIBACwqqfzL/irX7xpepIg7sydaC1CpYp86bC+UiG4C7QdKuuDrguY37n38kg5D5x6nOBIAjqgW45hUUcSJBVItS8nLtGrtopnyWJfr/bbfVT7MXMpJKEaDzPYgkAx12ObDMav6O9m+aj9n3zzGyNKDzmwkEk4IVHR1La0FfleTQ57d/gCjxDjgHLa7ayaXUYIyloPg+OdkMTkOTzMiFfVP3dCuXY7YHmNz2WuL8lPAhvVaEAYW4IPN0BZkseHjfxDKxPaAQrOMPSSYn826Y3XTyUGkBqFYu60VvwVawVhN4bn5oCkbfLHg8+wCCzbCrcrTwAC/cZubwO3/Ko3lzO+hxJDkbcHUgm8xYZziztIAxNGHORHF/6zgi6yvwOQfPNSWs4qWOFSBV3+JNRn+lvRRknRdGs0WPGZN9zIV4rRAuz1H+oh1WSfPdfDwf+qPeHME3sN0uUvNysdQPSnhi8crVv1hT1F+fv420olGKy0pnobvOCmw6uaBNInOm+xDHIsDt36t1P9OC3V9QPd4gs8BHRfssHOcTnptY/3cEwhTzW83QsbFgb9aQn/wDve6kKE9+i9Nd3XUeEIQ9E0MM2oI7vLyLDVg/YqBmxwEpfe6k8l4UI1UZlfn9TSBXhcaQ7VPNNeYS0j5lCEBP06LSV0Lx9YF4ad+sXdI0jAflBQodo6r",
                "MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ==",
                "MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se"
            }, jwk.X5C);

            Assert.Equal(chain, jwk.GetX509Chain());
        }

        [Fact]
        public void GetX509Chain()
        {
            //given
            var key = new Jwk();
            key.X5C = new List<string>
            {
                "MIIEoDCCAogCCQDU5pKjdLHJvzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MDU0OVoXDTMxMTIxNzE3MDU0OVowEjEQMA4GA1UEAwwHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBiqzJ6O7wLuFE42569qU3pR5CklXWE2XuNnt3LNglYOAOTy8j5xiImiIj+xN4K9qvPu30xbDL1EV83fom5zY2145RFvDc/FKKjmp1RrmL6rErRW2VbppuxSLXgNYUu6cffLbANCJdOmTPkAEwB+8GqnsEou00NFSM6LTJIihfpVln3mOr+wn9bQr7LQ62zdkj0i+rgxojyNhNNWVuGuRNV4kQRPhXMedUbKz73XoGOt3EXsyed81oMfkLZ0mh3Z3hAq0upUaCD6NeydVOTY62RgnUop7EdN+wruW3GRLReRq0ZtRFWNiaNfQA5ffSggzdtk7DDc6IU5vZDc/GZZP2VEZRzQ9HHw6Z6UfeRlL2H1YctGEEDIWX1sUYpHK1zzZtcOjbGsKpJtMuPFkVwJs9QOFEHtncxJaNN73e70/yv65PvuPhuFmKExVqEfu37IxM2Qoilii8/WBK9RonLe0qTLqNH2suXFkBDp9vhhUHGeho+m9ExhDQHpbRiXMw3EZDMICkvujhAqlK8wqcOfN0+urf8tzO9LtwX8czKbUq0R4HuGGdexd06/rK8GuUAr6aDSNdGkREeGl8EceYmBuGTmYRs/SqRRpW+k5O05gK7Nbvo2rU3BKL8y13AF95a5yXIZ3mJarXciv/WCv5sITcUtDIwZa/AkpaIGROQF2ejAgMBAAEwDQYJKoZIhvcNAQELBQADggIBACwqqfzL/irX7xpepIg7sydaC1CpYp86bC+UiG4C7QdKuuDrguY37n38kg5D5x6nOBIAjqgW45hUUcSJBVItS8nLtGrtopnyWJfr/bbfVT7MXMpJKEaDzPYgkAx12ObDMav6O9m+aj9n3zzGyNKDzmwkEk4IVHR1La0FfleTQ57d/gCjxDjgHLa7ayaXUYIyloPg+OdkMTkOTzMiFfVP3dCuXY7YHmNz2WuL8lPAhvVaEAYW4IPN0BZkseHjfxDKxPaAQrOMPSSYn826Y3XTyUGkBqFYu60VvwVawVhN4bn5oCkbfLHg8+wCCzbCrcrTwAC/cZubwO3/Ko3lzO+hxJDkbcHUgm8xYZziztIAxNGHORHF/6zgi6yvwOQfPNSWs4qWOFSBV3+JNRn+lvRRknRdGs0WPGZN9zIV4rRAuz1H+oh1WSfPdfDwf+qPeHME3sN0uUvNysdQPSnhi8crVv1hT1F+fv420olGKy0pnobvOCmw6uaBNInOm+xDHIsDt36t1P9OC3V9QPd4gs8BHRfssHOcTnptY/3cEwhTzW83QsbFgb9aQn/wDve6kKE9+i9Nd3XUeEIQ9E0MM2oI7vLyLDVg/YqBmxwEpfe6k8l4UI1UZlfn9TSBXhcaQ7VPNNeYS0j5lCEBP06LSV0Lx9YF4ad+sXdI0jAflBQodo6r",
                "MIIDpTCCAY0CCQCHPA/pgr0u7jANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdyb290LWNhMB4XDTIxMTIxOTE3MTUwM1oXDTM1MDgyODE3MTUwM1owFzEVMBMGA1UEAwwMaW50ZXJtaWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvJJcp8VR4hvtOME5Z+PYqPb6TL1JFBjnW3Bt+dMnnu3N6uMlIXrIb5ELX55OP3BLDmTJUPm1mEORBcBjuWeWI+CU1ZbF3QEkb+hzzgoRhkiAPDiVdmgA5vbSC0kRJxNJ7kGvLEIGQgVqSfFsuE09RCm6OuS2Qqin2W8pwWk05Ob+3hWW4UWgVhJqNSSONHFNeiRSdMXWQmywY33zosExTM4epJyFSS+dIIhR61zq15bbRXtnwBHBlVY/lT15zuMsu1j9SJ28M2qR14oyBzTdjHPK8pAeJOxK80zVnzlSAUZBhxoZioQyka85Ane+HyNv4A9wOFP/xs2Xot5+jtQowIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCCrsC3vu/CW2LJ5WwHgUC4Tr03v4/Sbs7di1GBn+RY2MWWTWnGhanInv0QGJmFsW0YtUNoRZR/qCsx/VCVy0uBfLHDkDFMu+OyGHygv940+ZVNVKB66wNosAkI2WIOFjcxD66o1jQAjJIp9gUOxvOuLh8SPJSBAmDVnhHOMbw+Gzv3F5MS7A6f7GvoIupRruLZtu0rQbOIt3CClsUui6D7A0VxsxJUpExMzn+teoOiquc1kpXhgK2bDlCS6IAGSDtbWXQAn983m1eD72IfM4yCWepOzpFs5OkDEYmBUmpnEQxeLQJH7UHs3/g9nxrC7xMVfOQhhbgWfyAx/TNP7Jt9yq/UOvBMVD05x5R7CJYR0cMi0IHnpSkY8NsiGxgOsWIHkvwc1ox2TVZyjR1zEuEkh0EN4/ur8OgaYSos5JfzSEVS00V9bFJnbhajNI8gkT2D+8zjdJ2FBieH7annnR4nZiYZecLjV605fr3+BeZZ6JRZKgMRQt2JQNA/iqKrHGmpU0REgOUXVrfnlu9KuvPnB4tlsIxRxlh/6o4lXdf9PME5U9t0g7JvH5EIzYyoFrdpSeNiFsg6DwhoXsp2lnUgD7WT27UVQ78PNk3BdqZiuQwSY62QK+xEpNvd8wts3uwFSzTat4QFlWuuT4M/o/NCbOttjGbS4m2t6gWJOFZbvQ==",
                "MIICpTCCAY0CCQDf1xHaEV6D6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxpbnRlcm1pZGlhdGUwHhcNMjExMjE5MTcxOTE0WhcNMzUwODI4MTcxOTE0WjASMRAwDgYDVQQDDAd0cmFwLm1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvys5QMXeOasAgqj+Rg+NBgjIK7fv3BrQPUu5PUu7tD2frWmzCHnBpodq8l5nJ+OiyQIEmLFJ1wuaBnmIJQejiWuRWhhdprFq4gjsC0xgI4oKP7oD3c5XglvazwM8c3AXWqqpEr9RzWR01TOouWYjcVRVHj/xcIzeHgYgmMvIACemBkk5G9T96+RbImmUP2P3KR2uYcXYjMAxegHqRxlcbOrGHOyvwE6qRPEELvOHNxDMd6rstfiaLOpqJ1MMnSM40Ee86NzszKM9oJOr4KJeQ94SdbtsZ+CUCGn+MbXSbu5yVNFSv+YcY6fAgJggauUShcRkH7iQ1OX6qxoO9WNkoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAi+mkYWKIIbTytJ7M6O7R0Si0wt/yNPUozx02ys/Tmh3ots1nvjXY+bCYDTPsRxwu0QpQA1dt/CNDS5slmvRxpoLs0tE3qfqFzDrPa+IHJ/Pz+UmNHcfSzSH7wP2biWGGOb0MUzS95qYM2U0Y+eNDNgE1FweDUIR8o1HuqomvlO2/qHAzjp+tcO/lJ4JKZRxn4YpiYopT1Xxaxw6fpb2aMbegjZsRtetxoIBekI8VIXgisUKOsYQ9gKqy2i50G9kZJAYllx+A3gg3+95USqUxiVE2lvobaOij4DlQbsGYX0brEym6/broMeZXJnLa0kN8ZcCaos2V/+jY2hQ3Ql/Se"
            };

            //when
            List<X509Certificate2> test = key.GetX509Chain();

            //then
            Assert.Equal(3, test.Count);
            Assert.Equal("CN=root-ca", test[0].Subject);
            Assert.Equal("CN=intermidiate", test[1].Subject);
            Assert.Equal("CN=trap.me", test[2].Subject);
        }

        [Fact]
        public void SetX5T()
        {
            //given
            var key = new Jwk();

            //when
            key.SetX5T(X509());

            //then
            Assert.Equal("5hJMjOCG0aFBwPGVCyAhepsmDwI", key.X5T);
        }

        [Fact]
        public void SetX5TSha256()
        {
            //given
            var key = new Jwk();

            //when
            key.SetX5TSha256(X509());

            //then
            Assert.Equal("uyIuvRrCqDBYz5XIDMk5z1CT5_Gpel_8GylIAFZxRVc", key.X5TSha256);
        }

        #region Test Utils

        private static RSA PrivRsaKey()
        {
            return X509().GetRSAPrivateKey();
        }

        private static RSA PubRsaKey()
        {
            return X509().GetRSAPublicKey();
        }

        private static X509Certificate2 X509()
        {
            return new X509Certificate2("jwt-2048.p12", "1", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }

        private List<X509Certificate2> X509Chain()
        {
            X509Certificate2Collection collection = new X509Certificate2Collection();
            collection.Import("chain.p12", "1", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            List<X509Certificate2> result = new List<X509Certificate2>();

            foreach (X509Certificate2 cert in collection)
            {
                Console.Out.WriteLine(Convert.ToBase64String(cert.RawData));
                result.Add(cert);
            }

            return result;
        }

        private static CngKey Ecc256Private(CngKeyUsages usage = CngKeyUsages.Signing)
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EccKey.New(x, y, d, usage);
        }

        private static CngKey Ecc256Public(CngKeyUsages usage = CngKeyUsages.Signing)
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return EccKey.New(x, y, usage: usage);
        }

        private static CngKey Ecc384Public()
        {
            byte[] x = { 70, 151, 220, 179, 62, 0, 79, 232, 114, 64, 58, 75, 91, 209, 232, 128, 7, 137, 151, 42, 13, 148, 15, 133, 93, 215, 7, 3, 136, 124, 14, 101, 242, 207, 192, 69, 212, 145, 88, 59, 222, 33, 127, 46, 30, 218, 175, 79 };
            byte[] y = { 189, 202, 196, 30, 153, 53, 22, 122, 171, 4, 188, 42, 71, 2, 9, 193, 191, 17, 111, 180, 78, 6, 110, 153, 240, 147, 203, 45, 152, 236, 181, 156, 232, 223, 227, 148, 68, 148, 221, 176, 57, 149, 44, 203, 83, 85, 75, 55 };

            return EccKey.New(x, y);
        }

        private static CngKey Ecc384Private()
        {
            byte[] x = { 70, 151, 220, 179, 62, 0, 79, 232, 114, 64, 58, 75, 91, 209, 232, 128, 7, 137, 151, 42, 13, 148, 15, 133, 93, 215, 7, 3, 136, 124, 14, 101, 242, 207, 192, 69, 212, 145, 88, 59, 222, 33, 127, 46, 30, 218, 175, 79 };
            byte[] y = { 189, 202, 196, 30, 153, 53, 22, 122, 171, 4, 188, 42, 71, 2, 9, 193, 191, 17, 111, 180, 78, 6, 110, 153, 240, 147, 203, 45, 152, 236, 181, 156, 232, 223, 227, 148, 68, 148, 221, 176, 57, 149, 44, 203, 83, 85, 75, 55 };
            byte[] d = { 137, 199, 183, 105, 188, 90, 128, 82, 116, 47, 161, 100, 221, 97, 208, 64, 173, 247, 9, 42, 186, 189, 181, 110, 24, 225, 254, 136, 75, 156, 242, 209, 94, 218, 58, 14, 33, 190, 15, 82, 141, 238, 207, 214, 159, 140, 247, 139 };

            return EccKey.New(x, y, d);
        }

        private static CngKey Ecc512Public()
        {
            byte[] x = { 0, 248, 73, 203, 53, 184, 34, 69, 111, 217, 230, 255, 108, 212, 241, 229, 95, 239, 93, 131, 100, 37, 86, 152, 87, 98, 170, 43, 25, 35, 80, 137, 62, 112, 197, 113, 138, 116, 114, 55, 165, 128, 8, 139, 148, 237, 109, 121, 40, 205, 3, 61, 127, 28, 195, 58, 43, 228, 224, 228, 82, 224, 219, 148, 204, 96 };
            byte[] y = { 0, 60, 71, 97, 112, 106, 35, 121, 80, 182, 20, 167, 143, 8, 246, 108, 234, 160, 193, 10, 3, 148, 45, 11, 58, 177, 190, 172, 26, 178, 188, 240, 91, 25, 67, 79, 64, 241, 203, 65, 223, 218, 12, 227, 82, 178, 66, 160, 19, 194, 217, 172, 61, 250, 23, 78, 218, 130, 160, 105, 216, 208, 235, 124, 46, 32 };

            return EccKey.New(x, y);
        }

        private static CngKey Ecc512Private()
        {
            byte[] x = { 0, 248, 73, 203, 53, 184, 34, 69, 111, 217, 230, 255, 108, 212, 241, 229, 95, 239, 93, 131, 100, 37, 86, 152, 87, 98, 170, 43, 25, 35, 80, 137, 62, 112, 197, 113, 138, 116, 114, 55, 165, 128, 8, 139, 148, 237, 109, 121, 40, 205, 3, 61, 127, 28, 195, 58, 43, 228, 224, 228, 82, 224, 219, 148, 204, 96 };
            byte[] y = { 0, 60, 71, 97, 112, 106, 35, 121, 80, 182, 20, 167, 143, 8, 246, 108, 234, 160, 193, 10, 3, 148, 45, 11, 58, 177, 190, 172, 26, 178, 188, 240, 91, 25, 67, 79, 64, 241, 203, 65, 223, 218, 12, 227, 82, 178, 66, 160, 19, 194, 217, 172, 61, 250, 23, 78, 218, 130, 160, 105, 216, 208, 235, 124, 46, 32 };
            byte[] d = { 0, 222, 129, 9, 133, 207, 123, 116, 176, 83, 95, 169, 29, 121, 160, 137, 22, 21, 176, 59, 203, 129, 62, 111, 19, 78, 14, 174, 20, 211, 56, 160, 83, 42, 74, 219, 208, 39, 231, 33, 84, 114, 71, 106, 109, 161, 116, 243, 166, 146, 252, 231, 137, 228, 99, 149, 152, 123, 201, 157, 155, 131, 181, 106, 179, 112 };

            return EccKey.New(x, y, d);
        }

#if NETSTANDARD || NET472
        private static ECDsa ECDSa256Public()
        {
            var x095 = new X509Certificate2("ecc256.p12", "12345");

            return x095.GetECDsaPublicKey();
        }

        private static ECDsa ECDSa256Private()
        {
            var x095 = new X509Certificate2("ecc256.p12", "12345", X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

            return Exportable(x095.GetECDsaPrivateKey());
        }

        private static ECDsa ECDSa384Public()
        {
            var x095 = new X509Certificate2("ecc384.p12", "12345");

            return x095.GetECDsaPublicKey();
        }

        private static ECDsa ECDSa384Private()
        {
            var x095 = new X509Certificate2("ecc384.p12", "12345", X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

            return Exportable(x095.GetECDsaPrivateKey());
        }

        private static ECDsa ECDSa521Public()
        {
            var x095 = new X509Certificate2("ecc521.p12", "12345");

            return x095.GetECDsaPublicKey();
        }

        private static ECDsa ECDSa521Private()
        {
            var x095 = new X509Certificate2("ecc521.p12", "12345", X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

            return Exportable(x095.GetECDsaPrivateKey());
        }

        // Make key exportable to avoid MS bugs with CNG interop
        private static ECDsa Exportable(ECDsa key)
        {
            if (key is ECDsaCng)
            {
                ECDsaCng cng = key as ECDsaCng;
                CngProperty pty = new CngProperty("Export Policy", BitConverter.GetBytes((int)(CngExportPolicies.AllowPlaintextExport)), CngPropertyOptions.Persist);
                cng.Key.SetProperty(pty);
            }

            return key;
        }
#endif
        #endregion Test Utils
    }
}
