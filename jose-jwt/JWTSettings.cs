using Jose.jwe;
using System.Collections.Generic;
using System;

namespace Jose
{
    /// <summary>
    /// JWT settings object.  JWT has a global DefaultSettings instance that can be used to set global defaults.  Additionally,
    /// every method in JWT supports adding an optional settings parameter to override the default settings just for that call.
    /// </summary>
    public class JwtSettings
    {
        private Dictionary<JwsAlgorithm, IJwsAlgorithm> jwsAlgorithms = new Dictionary<JwsAlgorithm, IJwsAlgorithm>
            {
                { JwsAlgorithm.none, new Plaintext()},
                { JwsAlgorithm.HS256, new HmacUsingSha("SHA256") },
                { JwsAlgorithm.HS384, new HmacUsingSha("SHA384") },
                { JwsAlgorithm.HS512, new HmacUsingSha("SHA512") },

                { JwsAlgorithm.RS256, new RsaUsingSha("SHA256") },
                { JwsAlgorithm.RS384, new RsaUsingSha("SHA384") },
                { JwsAlgorithm.RS512, new RsaUsingSha("SHA512") },

                { JwsAlgorithm.PS256, new RsaPssUsingSha(32) },
                { JwsAlgorithm.PS384, new RsaPssUsingSha(48) },
                { JwsAlgorithm.PS512, new RsaPssUsingSha(64) },
#if NET40
                { JwsAlgorithm.ES256, new EcdsaUsingSha(256) },
                { JwsAlgorithm.ES384, new EcdsaUsingSha(384) },
                { JwsAlgorithm.ES512, new EcdsaUsingSha(521) }
#elif NETSTANDARD1_4 || NET461 || NETSTANDARD2_0
                { JwsAlgorithm.ES256, new Jose.netstandard1_4.EcdsaUsingSha(256) },
                { JwsAlgorithm.ES384, new Jose.netstandard1_4.EcdsaUsingSha(384) },
                { JwsAlgorithm.ES512, new Jose.netstandard1_4.EcdsaUsingSha(521) }
#endif
            };

        private Dictionary<JwsAlgorithm, string> jwsAlgorithmsHeaderValue = new Dictionary<JwsAlgorithm, string>
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

        private Dictionary<string, JwsAlgorithm> jwsAlgorithmsAliases = new Dictionary<string, JwsAlgorithm>();

        private Dictionary<JweEncryption, IJweAlgorithm> encAlgorithms = new Dictionary<JweEncryption, IJweAlgorithm>
            {
                { JweEncryption.A128CBC_HS256, new AesCbcHmacEncryption(new HmacUsingSha("SHA256"), 256) },
                { JweEncryption.A192CBC_HS384, new AesCbcHmacEncryption(new HmacUsingSha("SHA384"), 384) },
                { JweEncryption.A256CBC_HS512, new AesCbcHmacEncryption(new HmacUsingSha("SHA512"), 512) },

                { JweEncryption.A128GCM, new AesGcmEncryption(128) },
                { JweEncryption.A192GCM, new AesGcmEncryption(192) },
                { JweEncryption.A256GCM, new AesGcmEncryption(256) }
            };

        private Dictionary<JweEncryption, string> encAlgorithmsHeaderValue = new Dictionary<JweEncryption, string>
            {
                { JweEncryption.A128CBC_HS256, "A128CBC-HS256" },
                { JweEncryption.A192CBC_HS384, "A192CBC-HS384" },
                { JweEncryption.A256CBC_HS512, "A256CBC-HS512" },
                { JweEncryption.A128GCM, "A128GCM" },
                { JweEncryption.A192GCM, "A192GCM" },
                { JweEncryption.A256GCM, "A256GCM" },
            };

        private Dictionary<string, JweEncryption> encAlgorithmsAliases = new Dictionary<string, JweEncryption>();

        private Dictionary<JweAlgorithm, IKeyManagement> keyAlgorithms = new Dictionary<JweAlgorithm, IKeyManagement>
            {
                { JweAlgorithm.RSA_OAEP, new RsaKeyManagement(true) },
                { JweAlgorithm.RSA_OAEP_256, new RsaOaep256KeyManagement() },
                { JweAlgorithm.RSA1_5, new RsaKeyManagement(false) },
                { JweAlgorithm.DIR, new DirectKeyManagement() },
                { JweAlgorithm.A128KW, new AesKeyWrapManagement(128) },
                { JweAlgorithm.A192KW, new AesKeyWrapManagement(192) },
                { JweAlgorithm.A256KW, new AesKeyWrapManagement(256) },
                { JweAlgorithm.ECDH_ES, new EcdhKeyManagement(true) },
                { JweAlgorithm.ECDH_ES_A128KW, new EcdhKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128)) },
                { JweAlgorithm.ECDH_ES_A192KW, new EcdhKeyManagementWithAesKeyWrap(192, new AesKeyWrapManagement(192)) },
                { JweAlgorithm.ECDH_ES_A256KW, new EcdhKeyManagementWithAesKeyWrap(256, new AesKeyWrapManagement(256)) },
                { JweAlgorithm.PBES2_HS256_A128KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128)) },
                { JweAlgorithm.PBES2_HS384_A192KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(192, new AesKeyWrapManagement(192)) },
                { JweAlgorithm.PBES2_HS512_A256KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(256, new AesKeyWrapManagement(256)) },
                { JweAlgorithm.A128GCMKW, new AesGcmKeyWrapManagement(128) },
                { JweAlgorithm.A192GCMKW, new AesGcmKeyWrapManagement(192) },
                { JweAlgorithm.A256GCMKW, new AesGcmKeyWrapManagement(256) }
            };
        private Dictionary<JweAlgorithm, string> keyAlgorithmsHeaderValue = new Dictionary<JweAlgorithm, string>
            {
                { JweAlgorithm.RSA1_5, "RSA1_5" },
                { JweAlgorithm.RSA_OAEP, "RSA-OAEP" },
                { JweAlgorithm.RSA_OAEP_256, "RSA-OAEP-256" },
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

        private Dictionary<string, JweAlgorithm> keyAlgorithmsAliases = new Dictionary<string, JweAlgorithm>();

        private Dictionary<JweCompression, ICompression> compressionAlgorithms = new Dictionary<JweCompression, ICompression>
        {
            { JweCompression.DEF, new DeflateCompression() }
        };

        private Dictionary<JweCompression, string> jweCompressionHeaderValue = new Dictionary<JweCompression, string>
        {
            { JweCompression.DEF, "DEF" }
        };

        private Dictionary<string, JweCompression> compressionAlgorithmsAliases = new Dictionary<string, JweCompression>();

#if NET40 || NET461
        private IJsonMapper jsMapper = new JSSerializerMapper();
#elif NETSTANDARD1_4 || NETSTANDARD2_0
        private IJsonMapper jsMapper = new NewtonsoftMapper();
#endif

        //Builder-style methods
        public JwtSettings RegisterJwa(JweAlgorithm alg, IKeyManagement impl)
        {
            keyAlgorithms[alg] = impl;
            return this;
        }

        /// <summary>
        /// Register an alias for the "alg" header that should point to a standard JWA key management algorithm
        /// </summary>
        public JwtSettings RegisterJwaAlias(string alias, JweAlgorithm alg)
        {
            keyAlgorithmsAliases[alias] = alg;
            return this;
        }

        /// <summary>
        /// Register an alias for the "enc" header that should point to a standard JWE encryption algorithm
        /// </summary>
        public JwtSettings RegisterJwe(JweEncryption alg, IJweAlgorithm impl)
        {
            encAlgorithms[alg] = impl;
            return this;
        }

        /// <summary>
        /// Register an alias for the "enc" header that should point to a standard JWE encryption algorithm
        /// </summary>
        public JwtSettings RegisterJweAlias(string alias, JweEncryption alg)
        {
            encAlgorithmsAliases[alias] = alg;
            return this;
        }

        public JwtSettings RegisterCompression(JweCompression alg, ICompression impl)
        {
            compressionAlgorithms[alg] = impl;
            return this;
        }

        /// <summary>
        /// Register an alias for the "zip" header that should point to a standard compression algorithm
        /// </summary>
        public JwtSettings RegisterCompressionAlias(string alias, JweCompression alg)
        {
            compressionAlgorithmsAliases[alias] = alg;
            return this;
        }


        public JwtSettings RegisterJws(JwsAlgorithm alg, IJwsAlgorithm impl)
        {
            jwsAlgorithms[alg] = impl;

            return this;
        }
        
        /// <summary>
        /// Register an alias for the "alg" header that should point to a standard JWS signing algorithm
        /// </summary>
        public JwtSettings RegisterJwsAlias(string alias, JwsAlgorithm alg)
        {
            jwsAlgorithmsAliases[alias] = alg;
            return this;
        }

        public JwtSettings RegisterMapper(IJsonMapper mapper)
        {
            jsMapper = mapper;

            return this;
        }

        //Properties
        public IJsonMapper JsonMapper
        {
            get { return jsMapper; }
            set { jsMapper = value; }
        }

        //JWS signing algorithm
        public IJwsAlgorithm Jws(JwsAlgorithm alg)
        {
            IJwsAlgorithm impl;
            return jwsAlgorithms.TryGetValue(alg, out impl) ? impl : null;
        }

        public string JwsHeaderValue(JwsAlgorithm algorithm)
        {
            return jwsAlgorithmsHeaderValue[algorithm];
        }

        public JwsAlgorithm JwsAlgorithmFromHeader(string headerValue)
        {
            foreach (var pair in jwsAlgorithmsHeaderValue)
            {
                if (pair.Value.Equals(headerValue)) return pair.Key;
            }

            //try alias
            JwsAlgorithm aliasMatch;
            if (jwsAlgorithmsAliases.TryGetValue(headerValue, out aliasMatch))
            {
                return aliasMatch;
            }

            throw new InvalidAlgorithmException(string.Format("JWS algorithm is not supported: {0}", headerValue));
        }

        //JWE encryption algorithm
        public IJweAlgorithm Jwe(JweEncryption alg)
        {
            IJweAlgorithm impl;
            return encAlgorithms.TryGetValue(alg, out impl) ? impl : null; ;
        }

        public string JweHeaderValue(JweEncryption algorithm)
        {
            return encAlgorithmsHeaderValue[algorithm];
        }

        public JweEncryption JweAlgorithmFromHeader(string headerValue)
        {
            foreach (var pair in encAlgorithmsHeaderValue)
            {
                if (pair.Value.Equals(headerValue)) return pair.Key;
            }

            //try alias
            JweEncryption aliasMatch;

            if (encAlgorithmsAliases.TryGetValue(headerValue, out aliasMatch))
            {
                return aliasMatch;
            }
            throw new InvalidAlgorithmException(string.Format("JWE algorithm is not supported: {0}", headerValue));
        }

        //JWA algorithm
        public IKeyManagement Jwa(JweAlgorithm alg)
        {
            IKeyManagement impl;
            return keyAlgorithms.TryGetValue(alg, out impl) ? impl : null;
        }

        public string JwaHeaderValue(JweAlgorithm alg)
        {
            return keyAlgorithmsHeaderValue[alg];
        }

        public JweAlgorithm JwaAlgorithmFromHeader(string headerValue)
        {
            foreach (var pair in keyAlgorithmsHeaderValue)
            {
                if (pair.Value.Equals(headerValue)) return pair.Key;
            }

            //try alias
            JweAlgorithm aliasMatch;
            if (keyAlgorithmsAliases.TryGetValue(headerValue, out aliasMatch))
            {
                return aliasMatch;
            }
            throw new InvalidAlgorithmException(string.Format("JWA algorithm is not supported: {0}.", headerValue));
        }

        //Compression
        public ICompression Compression(JweCompression alg)
        {
            ICompression impl;
            return compressionAlgorithms.TryGetValue(alg, out impl) ? impl : null;
        }

        public ICompression Compression(string alg)
        {
            return Compression(CompressionAlgFromHeader(alg));
        }

        public string CompressionHeader(JweCompression value)
        {
            return jweCompressionHeaderValue[value];
        }

        public JweCompression CompressionAlgFromHeader(string header)
        {
            foreach (var pair in jweCompressionHeaderValue)
            {
                if (pair.Value.Equals(header)) return pair.Key;
            }

            //try alias
            JweCompression aliasMatch;

            if (compressionAlgorithmsAliases.TryGetValue(header, out aliasMatch))
            {
                return aliasMatch;
            }

            throw new InvalidAlgorithmException(string.Format("Compression algorithm is not supported: {0}.", header));
        }
    }
}
