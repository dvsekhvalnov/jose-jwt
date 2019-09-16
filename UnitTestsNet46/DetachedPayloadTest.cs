using Jose;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace UnitTests
{
    public class DetachedPayloadTest
    {
        
        [Fact]
        public void UKOpenBankingSignatureWorks()
        {
            var cert = X509();
            DateTime start = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            long unixTime = (long)DateTime.UtcNow.Subtract(start).TotalSeconds;
            string payload = @"{""toto"": ""titi""}";
          
            var headers = new Dictionary<string, object>()
            {
                { "b64", false },
                { "http://openbanking.org.uk/iat", unixTime },
                { "http://openbanking.org.uk/tan", "openbanking.org.uk" },
                { "crit", new string[] {"b64", "http://openbanking.org.uk/iat", "http://openbanking.org.uk/iss", "http://openbanking.org.uk/tan" } },
                { "kid", cert.Thumbprint.ToLower() },
                { "http://openbanking.org.uk/iss", "5d7ce654aba91f0019a87709" },
                { "alg", "PS256" }
            };
            var privateKey = cert.GetRSAPrivateKey();
            var publicKey = (RSACryptoServiceProvider)cert.PublicKey.Key;
            
            string token = Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.PS256, extraHeaders: headers);
            Console.Out.WriteLine("PS256 = {0}", token);
            string[] parts = token.Split('.');
            Assert.Equal(3, parts.Length);
            Assert.True(string.IsNullOrEmpty(parts[1]));
            
            var decodedToken = Jose.JWT.DecodeDetached(token, System.Text.Encoding.UTF8.GetBytes(payload), publicKey);
            Assert.Equal(payload, decodedToken);

        }
        private X509Certificate2 X509()
        {
            return new X509Certificate2("jwt-2048.p12", "1", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }

        private RSA PrivRsaKey()
        {
            return X509().GetRSAPrivateKey();
        }

        private RSACryptoServiceProvider PubKey()
        {
            return (RSACryptoServiceProvider)X509().PublicKey.Key;
        }

        private RSA PubRsaKey()
        {
            return X509().GetRSAPublicKey();
        }
    }
}
