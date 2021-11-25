using Jose.keys;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Jose
{
    public class JWK
    {        
        public static class KeyTypes
        {
            public const string OCT = "oct";
            public const string EC = "EC";
            public const string RSA = "RSA";
        }

        public static class KeyUsage
        {
            public const string Signature = "sig";
            public const string Encryption = "enc";
        }

        public static class KeyOperations
        {
            public const string Sign = "sign";
            public const string Verify = "verify";
            public const string Encrypt = "encrypt";
            public const string Decrypt = "decrypt";
            public const string WrapKey = "wrapKey";
            public const string UnwrapKey = "unwrapKey";
            public const string DeriveKey = "deriveKey";
            public const string DeriveBits = "deriveBits";
        }

        private byte[] octKey;
        private RSA rsaKey;
        private CngKey eccCngKey;

    #if NETSTANDARD || NET472
        private ECDsa ecdsaKey;
    #endif

        // General
        public string Kty { get; set; }
        public string Use { get; set; }
        public string Alg { get; set; }
        public string KeyId { get; set; }
        public List<string> KeyOps { get; set; }

        // Symmetric keys
        public string K { get; set; }


        /* 
         * RSA keys
         */

        // Modulus
        public string N { get; set; }

        // Public exponent
        public string E { get; set; }

        // Private exponent or private part of ECC key
        public string D { get; set; }

        // First prime
        public string P { get; set; }

        // First factor CRT exponent
        public string DP { get; set; }

        // Second prime
        public string Q { get; set; }

        // Second factor CRT exponent
        public string DQ { get; set; }

        // First CRT coefficient
        public string QI { get; set; }

        /*
         * Elliptic keys
         */

        // Curve
        public string Crv { get; set; }

        // Public part, X coordinate on curve
        public string X { get; set; }

        // Public part, Y coordinate on curve
        public string Y { get; set; }        

        public RSA RsaKey()
        {
            if (rsaKey == null && E != null && N != null)
            {
                RSAParameters param = new RSAParameters();
                param.Modulus = Base64Url.Decode(N);
                param.Exponent = Base64Url.Decode(E);

                if (D != null)
                {
                    param.D = Base64Url.Decode(D);
                }

                if (P != null)
                {
                    param.P = Base64Url.Decode(P);
                }

                if (Q != null)
                {
                    param.Q = Base64Url.Decode(Q);
                }

                if (DP != null)
                {
                    param.DP = Base64Url.Decode(DP);
                }

                if (DQ != null)
                {
                    param.DQ = Base64Url.Decode(DQ);
                }

                if (QI != null)
                {
                    param.InverseQ = Base64Url.Decode(QI);
                }

                rsaKey = RSA.Create();
                rsaKey.ImportParameters(param);
            }

            return rsaKey;
        }

        public byte[] OctKey()
        {
            if (octKey == null && K != null)
            {
                octKey = Base64Url.Decode(K);
            }

            return octKey;
        }

     
        public ECDsa ECDsaKey ()
        {
    #if NETSTANDARD || NET472
            if (ecdsaKey == null && X != null && Y != null && Crv !=null)
            {
                ECParameters param = new ECParameters();

                param.Q = new ECPoint();
                param.Q.X = Base64Url.Decode(X);
                param.Q.Y = Base64Url.Decode(Y);

                // TODO: fix
                param.Curve = NameToCurve(Crv);

                if (D != null)
                {
                    param.D = Base64Url.Decode(D);
                }


                ecdsaKey = ECDsa.Create();
                ecdsaKey.ImportParameters(param);
            }

            return ecdsaKey;
    #else
            throw new NotImplementedException("Not supported, requires .NET 4.7.2+ or NETSTANDARD");
    #endif
        }

        public CngKey CngKey(CngKeyUsages usage = CngKeyUsages.Signing)
        {
            if (eccCngKey == null && X != null && Y != null)
            {
                byte[] d = (D != null) ? Base64Url.Decode(D) : null;

                eccCngKey = EccKey.New(Base64Url.Decode(X), Base64Url.Decode(Y), d, usage);
            }

            return eccCngKey;
        }

        public JWK()
        {

        }

        public JWK(string crv, string x, string y, string d = null)
        {
            Kty = KeyTypes.EC;
            Crv = crv;
            X = x;
            Y = y;
            D = d;
        }

        public JWK(string e, string n, string p = null, string q = null, string d = null, string dp = null, string dq = null, string qi = null)
        {
            Kty = KeyTypes.RSA;
            E = e;
            N = n;
            P = p;
            Q = q;
            D = d;
            DP = dp;
            DQ = dq;
            QI = qi;
        }

        public JWK(byte[] key)
        {
            Kty = KeyTypes.OCT;
            K = Base64Url.Encode(key);
            octKey = key;
        }

        public JWK(ECDsa key, bool isPrivate = true)
        {
          #if NETSTANDARD || NET472
            ecdsaKey = key;
            Kty = KeyTypes.EC;           

            ECParameters param = key.ExportParameters(isPrivate);

            X = Base64Url.Encode(param.Q.X);
            Y = Base64Url.Encode(param.Q.Y);

            if (param.D != null)
            {
                D = Base64Url.Encode(param.D);
            }

            Crv = CurveToName(param.Curve);

          #else
            throw new NotImplementedException("Not supported, requires .NET 4.7.2+ or NETSTANDARD"); 
          #endif
        }

        public JWK(RSA key, bool isPrivate = true)
        {
            rsaKey = key;
            Kty = KeyTypes.RSA;

            RSAParameters param = key.ExportParameters(isPrivate);

            N = Base64Url.Encode(param.Modulus);
            E = Base64Url.Encode(param.Exponent);

            if (param.D !=null)
            {
                D = Base64Url.Encode(param.D);
            }

            if (param.P !=null)
            {
                P = Base64Url.Encode(param.P);
            }

            if (param.DP !=null)
            {
                DP = Base64Url.Encode(param.DP);
            }

            if (param.Q !=null)
            {
                Q = Base64Url.Encode(param.Q);
            }

            if (param.DQ !=null)
            {
                DQ = Base64Url.Encode(param.DQ);
            }

            if (param.InverseQ !=null)
            {
                QI = Base64Url.Encode(param.InverseQ);
            }
        }

        public JWK(CngKey key, bool isPrivate = true)
        {
            eccCngKey = key;

            Kty = JWK.KeyTypes.EC;

            var eccKey = EccKey.Export(key, isPrivate);

            Crv = eccKey.Curve();

            X = Base64Url.Encode(eccKey.X);
            Y = Base64Url.Encode(eccKey.Y);

            if (eccKey.D != null)
            { 
                D = Base64Url.Encode(eccKey.D);
            }            
        }

        public IDictionary<string, object> ToDictionary()
        {
            var result = new Dictionary<string, object>();

            result["kty"] = Kty;

            if (KeyId != null) { result["kid"] = KeyId; }
            if (Use != null) { result["use"] = Use; }
            if (KeyOps != null) { result["key_ops"] = KeyOps; }
            if (Alg != null) { result["alg"] = Alg; }
            
            if (Kty == JWK.KeyTypes.OCT)
            {
                result["k"] = K;
            }     
            
            if (Kty == JWK.KeyTypes.RSA)
            {
                result["e"] = E;
                result["n"] = N;

                if (D != null) { result["d"] = D; }
                if (P != null) { result["p"] = P; }
                if (Q != null) { result["q"] = Q; }
                if (DP != null) { result["dp"] = DP; }
                if (DQ != null) { result["dq"] = DQ; }
                if (QI != null) { result["qi"] = QI; }
            }

            if (Kty == JWK.KeyTypes.EC)
            {                
                result["crv"] = Crv;
                result["x"] = X;
                result["y"] = Y;

                if (D != null) { result["d"] = D; }
            }


            return result;
        }

        public static JWK FromDictionary(IDictionary<string, object> data)
        {
            var key = new JWK
            {
                Kty = Dictionaries.Get<string>(data, "kty"),                
                Use = Dictionaries.Get<string>(data, "use"),                
                Alg = Dictionaries.Get<string>(data, "alg"),
                KeyId = Dictionaries.Get<string>(data, "kid"),
                KeyOps = Dictionaries.GetList<string>(data, "key_ops"),

                K = Dictionaries.Get<string>(data, "k"),  
                E = Dictionaries.Get<string>(data, "e"),  
                N = Dictionaries.Get<string>(data, "n"),  
                D = Dictionaries.Get<string>(data, "d"),  
                P = Dictionaries.Get<string>(data, "p"),  
                Q = Dictionaries.Get<string>(data, "q"),  
                DP = Dictionaries.Get<string>(data, "dp"),  
                DQ = Dictionaries.Get<string>(data, "dq"),  
                QI = Dictionaries.Get<string>(data, "qi"),

                Crv = Dictionaries.Get<string>(data, "crv"),
                X = Dictionaries.Get<string>(data, "x"),
                Y = Dictionaries.Get<string>(data, "y"),
            };
            

            return key;
        }

        public string ToJson(IJsonMapper mapper = null)
        {
            return mapper.Serialize(ToDictionary());
        }

        public static JWK FromJson(string json, IJsonMapper mapper = null)
        {
            return JWK.FromDictionary(
                mapper.Parse<IDictionary<string, object>>(json)
            );
        }

#if NETSTANDARD || NET472
        private static string CurveToName(ECCurve curve)
        {
            curve.Oid.FriendlyName = curve.Oid.FriendlyName;

            if (ECCurve.NamedCurves.nistP256.Oid.Value == curve.Oid.Value || ECCurve.NamedCurves.nistP256.Oid.FriendlyName == curve.Oid.FriendlyName)
            {
                return "P-256";
            }

            if (ECCurve.NamedCurves.nistP384.Oid.Value == curve.Oid.Value || ECCurve.NamedCurves.nistP384.Oid.FriendlyName == curve.Oid.FriendlyName)
            {
                return "P-384";
            }

            if (ECCurve.NamedCurves.nistP521.Oid.Value == curve.Oid.Value || ECCurve.NamedCurves.nistP521.Oid.FriendlyName == curve.Oid.FriendlyName)
            {
                return "P-521";
            }

            return null;
        }

        private static ECCurve NameToCurve(string name)
        {
            switch (name)
            {
                case "P-256": return ECCurve.NamedCurves.nistP256;
                case "P-284": return ECCurve.NamedCurves.nistP384;
                case "P-521": return ECCurve.NamedCurves.nistP521;
            }

            throw new ArgumentException("Unsupported curve: " + name);
        }
#endif
    }
}
