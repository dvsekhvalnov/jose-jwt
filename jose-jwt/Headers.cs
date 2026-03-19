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

        private static readonly Dictionary<JweAlgorithm, string> keyToHeader = new Dictionary<JweAlgorithm, string>
        {
            { JweAlgorithm.RSA1_5, "RSA1_5" },
            { JweAlgorithm.RSA_OAEP, "RSA-OAEP" },
            { JweAlgorithm.RSA_OAEP_256, "RSA-OAEP-256" },
            { JweAlgorithm.RSA_OAEP_384, "RSA-OAEP-384" },
            { JweAlgorithm.RSA_OAEP_512, "RSA-OAEP-512" },
            { JweAlgorithm.DIR, "dir" },
            { JweAlgorithm.A128KW, "A128KW" },
            { JweAlgorithm.A256KW, "A256KW" },
            { JweAlgorithm.A192KW, "A192KW" },
            { JweAlgorithm.ECDH_ES, "ECDH-ES" },
            { JweAlgorithm.ECDH_ES_A128KW, "ECDH-ES+A128KW" },
            { JweAlgorithm.ECDH_ES_A192KW, "ECDH-ES+A192KW" },
            { JweAlgorithm.ECDH_ES_A256KW, "ECDH-ES+A256KW" },
            { JweAlgorithm.PBES2_HS256_A128KW, "PBES2-HS256+A128KW" },
            { JweAlgorithm.PBES2_HS384_A192KW, "PBES2-HS384+A192KW" },
            { JweAlgorithm.PBES2_HS512_A256KW, "PBES2-HS512+A256KW" },
            { JweAlgorithm.A128GCMKW, "A128GCMKW" },
            { JweAlgorithm.A192GCMKW, "A192GCMKW" },
            { JweAlgorithm.A256GCMKW, "A256GCMKW" },
        };

        private static readonly Dictionary<string, JweAlgorithm> headerToKey = new Dictionary<string, JweAlgorithm>
        {
            { "RSA1_5", JweAlgorithm.RSA1_5 },
            { "RSA-OAEP", JweAlgorithm.RSA_OAEP },
            { "RSA-OAEP-256", JweAlgorithm.RSA_OAEP_256 },
            { "RSA-OAEP-384", JweAlgorithm.RSA_OAEP_384 },
            { "RSA-OAEP-512", JweAlgorithm.RSA_OAEP_512 },
            { "dir", JweAlgorithm.DIR },
            { "A128KW", JweAlgorithm.A128KW },
            { "A256KW", JweAlgorithm.A256KW },
            { "A192KW", JweAlgorithm.A192KW },
            { "ECDH-ES", JweAlgorithm.ECDH_ES },
            { "ECDH-ES+A128KW", JweAlgorithm.ECDH_ES_A128KW },
            { "ECDH-ES+A192KW", JweAlgorithm.ECDH_ES_A192KW },
            { "ECDH-ES+A256KW", JweAlgorithm.ECDH_ES_A256KW },
            { "PBES2-HS256+A128KW", JweAlgorithm.PBES2_HS256_A128KW },
            { "PBES2-HS384+A192KW", JweAlgorithm.PBES2_HS384_A192KW },
            { "PBES2-HS512+A256KW", JweAlgorithm.PBES2_HS512_A256KW },
            { "A128GCMKW", JweAlgorithm.A128GCMKW },
            { "A192GCMKW", JweAlgorithm.A192GCMKW  },
            { "A256GCMKW", JweAlgorithm.A256GCMKW },
        };

        private readonly static Dictionary<JweCompression, string> zipToHeader = new Dictionary<JweCompression, string>
        {
            { JweCompression.DEF, "DEF" }
        };

        private readonly static Dictionary<string, JweCompression> headerToZip = new Dictionary<string, JweCompression>
        {
            { "DEF", JweCompression.DEF }
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
    
        public static JweAlgorithm? Jwa(string header)
        {
            JweAlgorithm alg;

            if (headerToKey.TryGetValue(header, out alg))
            {
                return alg;
            }

            return null;
        }
        public static string Jwa(JweAlgorithm alg)
        {
            return keyToHeader[alg];
        }

        public static JweCompression? Zip(string header)
        {
            JweCompression alg;

            if (headerToZip.TryGetValue(header, out alg))
            {
                return alg;
            }

            return null;
        }
        public static string Zip(JweCompression alg)
        {
            return zipToHeader[alg];
        }
    }
}
