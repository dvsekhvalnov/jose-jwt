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

    }
}
