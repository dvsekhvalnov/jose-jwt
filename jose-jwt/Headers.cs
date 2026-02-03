using Jose;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Jose
{
    public static class Headers
    {
        private readonly static Dictionary<JweEncryption, string> encToHeader = new Dictionary<JweEncryption, string>
        {
            { JweEncryption.A128CBC_HS256, "A128CBC-HS256" },
            { JweEncryption.A192CBC_HS384, "A192CBC-HS384" },
            { JweEncryption.A256CBC_HS512, "A256CBC-HS512" },
            { JweEncryption.A128GCM, "A128GCM" },
            { JweEncryption.A192GCM, "A192GCM" },
            { JweEncryption.A256GCM, "A256GCM" },
        };

        private readonly static Dictionary<string, JweEncryption> headerToEnc = new Dictionary<string, JweEncryption>
        {
            { "A128CBC-HS256", JweEncryption.A128CBC_HS256 },
            { "A192CBC-HS384", JweEncryption.A192CBC_HS384 },
            { "A256CBC-HS512", JweEncryption.A256CBC_HS512 },
            { "A128GCM", JweEncryption.A128GCM },
            { "A192GCM", JweEncryption.A192GCM },
            { "A256GCM", JweEncryption.A256GCM },
        };

        private readonly static Dictionary<JwsAlgorithm, string> sigToHeader = new Dictionary<JwsAlgorithm, string>
        {
            { JwsAlgorithm.none, "none" },
            { JwsAlgorithm.HS256, "HS256" },
            { JwsAlgorithm.HS384, "HS384" },
            { JwsAlgorithm.HS512, "HS512" },
            { JwsAlgorithm.RS256, "RS256" },
            { JwsAlgorithm.RS384, "RS384" },
            { JwsAlgorithm.RS512, "RS512" },
            { JwsAlgorithm.ES256, "ES256" },
            { JwsAlgorithm.ES384, "ES384" },
            { JwsAlgorithm.ES512, "ES512" },
            { JwsAlgorithm.PS256, "PS256" },
            { JwsAlgorithm.PS384, "PS384" },
            { JwsAlgorithm.PS512, "PS512" },
        };

        private readonly static Dictionary<string, JwsAlgorithm> headerToSig = new Dictionary<string, JwsAlgorithm>
        {
            { "none", JwsAlgorithm.none },
            { "HS256", JwsAlgorithm.HS256 },
            { "HS384", JwsAlgorithm.HS384 },
            { "HS512", JwsAlgorithm.HS512 },
            { "RS256", JwsAlgorithm.RS256 },
            { "RS384", JwsAlgorithm.RS384 },
            { "RS512", JwsAlgorithm.RS512 },
            { "ES256", JwsAlgorithm.ES256 },
            { "ES384", JwsAlgorithm.ES384 },
            { "ES512", JwsAlgorithm.ES512 },
            { "PS256", JwsAlgorithm.PS256 },
            { "PS384", JwsAlgorithm.PS384 },
            { "PS512", JwsAlgorithm.PS512 },
        };

        public static JweEncryption? Jwe(string header)
        {
            JweEncryption alg;

            if(headerToEnc.TryGetValue(header, out alg))
            {
                return alg;
            }

            return null;
        }
        public static string Jwe(JweEncryption alg)
        {
            return encToHeader[alg];
        }

        public static JwsAlgorithm? Jws(string header)
        {
            JwsAlgorithm alg;

            if (headerToSig.TryGetValue(header, out alg))
            {
                return alg;
            }

            return null;
        }
        public static string Jws(JwsAlgorithm alg)
        {
            return sigToHeader[alg];
        }
    }
}
