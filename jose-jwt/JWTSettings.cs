using Jose;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Jose
{
    /// <summary>
    /// JWT settings object.  JWT has a global DefaultSettings instance that can be used to set global defaults.  Additionally,
    /// every method in JWT supports adding an optional settings parameter to override the default settings just for that call.
    /// </summary>
    public class JwtSettings
    {
        public JwtSettings()
        {
#if NET472 || NETSTANDARD2_1 || NET
	    // By giving the Unix ECDHKeyManagement implementation to windows, we enable windows version of it to work with not only CngKey but also ECDiffieHellman.
            // Initially this was implemented separately, but unit tests were failing on windows due to the lack of ECDiffieHellman support. 
            // Since we don't know what the keys will be provided until runtime, and the registration happens before runtime, we need to make sure 
            // on windows it will also supports ECDiffieHellman. 
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES], new EcdhKeyManagementWin(true, new EcdhKeyManagementUnix(true)));
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES_A128KW], new EcdhKeyManagementWinWithAesKeyWrap(128, new AesKeyWrapManagement(128), new EcdhKeyManagementUnixWithAesKeyWrap(128, new AesKeyWrapManagement(128))));
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES_A192KW], new EcdhKeyManagementWinWithAesKeyWrap(192, new AesKeyWrapManagement(192), new EcdhKeyManagementUnixWithAesKeyWrap(192, new AesKeyWrapManagement(192))));
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES_A256KW], new EcdhKeyManagementWinWithAesKeyWrap(256, new AesKeyWrapManagement(256), new EcdhKeyManagementUnixWithAesKeyWrap(256, new AesKeyWrapManagement(256))));
            }
            else
            {
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES], new EcdhKeyManagementUnix(true));
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES_A128KW], new EcdhKeyManagementUnixWithAesKeyWrap(128, new AesKeyWrapManagement(128)));
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES_A192KW], new EcdhKeyManagementUnixWithAesKeyWrap(192, new AesKeyWrapManagement(192)));
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES_A256KW], new EcdhKeyManagementUnixWithAesKeyWrap(256, new AesKeyWrapManagement(256)));
            }
#else
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES], new EcdhKeyManagementWin(true, new EcdhKeyManagementUnix(true)));
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES_A128KW], new EcdhKeyManagementWinWithAesKeyWrap(128, new AesKeyWrapManagement(128), new EcdhKeyManagementUnixWithAesKeyWrap(128, new AesKeyWrapManagement(128))));
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES_A192KW], new EcdhKeyManagementWinWithAesKeyWrap(192, new AesKeyWrapManagement(192), new EcdhKeyManagementUnixWithAesKeyWrap(192, new AesKeyWrapManagement(192))));
                keyAlgorithms.Add(keyAlgorithmsHeaderValue[JweAlgorithm.ECDH_ES_A256KW], new EcdhKeyManagementWinWithAesKeyWrap(256, new AesKeyWrapManagement(256), new EcdhKeyManagementUnixWithAesKeyWrap(256, new AesKeyWrapManagement(256))));
#endif
        }
        
        private readonly Dictionary<JwsAlgorithm, IJwsAlgorithm> jwsAlgorithms = new Dictionary<JwsAlgorithm, IJwsAlgorithm>
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
#elif NET461_OR_GREATER || NETSTANDARD || NET
            { JwsAlgorithm.ES256, new Jose.netstandard1_4.EcdsaUsingSha(256) },
            { JwsAlgorithm.ES384, new Jose.netstandard1_4.EcdsaUsingSha(384) },
            { JwsAlgorithm.ES512, new Jose.netstandard1_4.EcdsaUsingSha(521) }
#endif
        };

        private readonly Dictionary<JwsAlgorithm, string> jwsAlgorithmsHeaderValue = new Dictionary<JwsAlgorithm, string>
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

        private readonly Dictionary<string, JwsAlgorithm> jwsAlgorithmsAliases = new Dictionary<string, JwsAlgorithm>();

        private readonly Dictionary<string, IJweAlgorithm> encAlgorithms = new Dictionary<string, IJweAlgorithm>
        {
            { encAlgorithmsHeaderValue[JweEncryption.A128CBC_HS256], new AesCbcHmacEncryption(new HmacUsingSha("SHA256"), 256) },
            { encAlgorithmsHeaderValue[JweEncryption.A192CBC_HS384], new AesCbcHmacEncryption(new HmacUsingSha("SHA384"), 384) },
            { encAlgorithmsHeaderValue[JweEncryption.A256CBC_HS512], new AesCbcHmacEncryption(new HmacUsingSha("SHA512"), 512) },

            { encAlgorithmsHeaderValue[JweEncryption.A128GCM], new AesGcmEncryption(128) },
            { encAlgorithmsHeaderValue[JweEncryption.A192GCM], new AesGcmEncryption(192) },
            { encAlgorithmsHeaderValue[JweEncryption.A256GCM], new AesGcmEncryption(256) }
        };

        private readonly static Dictionary<JweEncryption, string> encAlgorithmsHeaderValue = new Dictionary<JweEncryption, string>
        {
            { JweEncryption.A128CBC_HS256, "A128CBC-HS256" },
            { JweEncryption.A192CBC_HS384, "A192CBC-HS384" },
            { JweEncryption.A256CBC_HS512, "A256CBC-HS512" },
            { JweEncryption.A128GCM, "A128GCM" },
            { JweEncryption.A192GCM, "A192GCM" },
            { JweEncryption.A256GCM, "A256GCM" },
        };

        private readonly Dictionary<string, JweEncryption> encAlgorithmsAliases = new Dictionary<string, JweEncryption>();

        private readonly Dictionary<string, IKeyManagement> keyAlgorithms = new Dictionary<string, IKeyManagement>
        {
            { keyAlgorithmsHeaderValue[JweAlgorithm.RSA_OAEP], new RsaKeyManagement(true) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.RSA_OAEP_256], new RsaOaepKeyManagement(256) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.RSA_OAEP_384], new RsaOaepKeyManagement(384) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.RSA_OAEP_512], new RsaOaepKeyManagement(512) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.RSA1_5], new RsaKeyManagement(false) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.DIR], new DirectKeyManagement() },
            { keyAlgorithmsHeaderValue[JweAlgorithm.A128KW], new AesKeyWrapManagement(128) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.A192KW], new AesKeyWrapManagement(192) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.A256KW], new AesKeyWrapManagement(256) },
            
            // PBKDF2 iterations limited per OWASP reccomendation: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
            { keyAlgorithmsHeaderValue[JweAlgorithm.PBES2_HS256_A128KW], new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128), 310000) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.PBES2_HS384_A192KW], new Pbse2HmacShaKeyManagementWithAesKeyWrap(192, new AesKeyWrapManagement(192), 250000) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.PBES2_HS512_A256KW], new Pbse2HmacShaKeyManagementWithAesKeyWrap(256, new AesKeyWrapManagement(256), 120000) },

            { keyAlgorithmsHeaderValue[JweAlgorithm.A128GCMKW], new AesGcmKeyWrapManagement(128) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.A192GCMKW], new AesGcmKeyWrapManagement(192) },
            { keyAlgorithmsHeaderValue[JweAlgorithm.A256GCMKW], new AesGcmKeyWrapManagement(256) }
        };

        private static readonly Dictionary<JweAlgorithm, string> keyAlgorithmsHeaderValue = new Dictionary<JweAlgorithm, string>
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

        private readonly Dictionary<string, JweAlgorithm> keyAlgorithmsAliases = new Dictionary<string, JweAlgorithm>();

        private readonly Dictionary<JweCompression, ICompression> compressionAlgorithms = new Dictionary<JweCompression, ICompression>
        {
            { 
                // 250Kb limited decompression buffer
                JweCompression.DEF, new DeflateCompression(250 * 1024) 
            }
        };

        private readonly static Dictionary<JweCompression, string> jweCompressionHeaderValue = new Dictionary<JweCompression, string>
        {
            { JweCompression.DEF, "DEF" }
        };

        private readonly Dictionary<string, JweCompression> compressionAlgorithmsAliases = new Dictionary<string, JweCompression>();

#if NETFRAMEWORK
        private IJsonMapper jsMapper = new JSSerializerMapper();
#elif NETSTANDARD1_4
        private IJsonMapper jsMapper = new NewtonsoftMapper();
#elif NETSTANDARD2_1 || NET
        private IJsonMapper jsMapper = new JsonMapper();
#endif

        /// <summary>
        /// Register Jwa implementation, will override existing one if any
        /// </summary>
        public JwtSettings RegisterJwa(JweAlgorithm alg, IKeyManagement impl)
        {
            keyAlgorithms[keyAlgorithmsHeaderValue[alg]] = impl;
            return this;
        }

        /// <summary>
        /// Register Jwa implementation, will override existing one if any
        /// </summary>
        public JwtSettings RegisterJwa(string alg, IKeyManagement impl)
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
        /// Register Jwe implementation, will override existing one if any
        /// </summary>
        public JwtSettings RegisterJwe(JweEncryption alg, IJweAlgorithm impl)
        {
            encAlgorithms[encAlgorithmsHeaderValue[alg]] = impl;
            return this;
        }

        /// <summary>
        /// Register Jwe implementation, will override existing one if any
        /// </summary>
        public JwtSettings RegisterJwe(string alg, IJweAlgorithm impl)
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

        /// Register Compression implementation, will override existing one if any
        public JwtSettings RegisterCompression(JweCompression alg, ICompression impl)
        {
            compressionAlgorithms[alg] = impl;
            return this;
        }

        public JwtSettings RegisterCompression(string alg, ICompression impl)
        {
            //compressionAlgorithms[alg] = impl;
            //return this;
            throw new NotImplementedException("TODO");
        }

        /// <summary>
        /// Register an alias for the "zip" header that should point to a standard compression algorithm
        /// </summary>
        public JwtSettings RegisterCompressionAlias(string alias, JweCompression alg)
        {
            compressionAlgorithmsAliases[alias] = alg;
            return this;
        }

        /// <summary>
        /// Register Jws implementation, will override existing one if any
        /// </summary>
        public JwtSettings RegisterJws(JwsAlgorithm alg, IJwsAlgorithm impl)
        {
            jwsAlgorithms[alg] = impl;

            return this;
        }

        /// <summary>
        /// Register Jws implementation, will override existing one if any
        /// </summary>
        public JwtSettings RegisterJws(string alg, IJwsAlgorithm impl)
        {
            //jwsAlgorithms[alg] = impl;

            //return this;
            throw new NotImplementedException("TODO");
        }

        /// <summary>
        /// Register an alias for the "alg" header that should point to a standard JWS signing algorithm
        /// </summary>
        public JwtSettings RegisterJwsAlias(string alias, JwsAlgorithm alg)
        {
            jwsAlgorithmsAliases[alias] = alg;
            return this;
        }

        /// <summary>
        /// Deregister Jws implementation. Subsequent calls to Decode/Encode for given alg will throw 'InvalidAlgorithmException'.
        /// Note: this method is not updating alg aliases. One should take care of it manually.
        /// </summary>
        public JwtSettings DeregisterJws(JwsAlgorithm alg)
        {
            jwsAlgorithms.Remove(alg);

            return this;
        }

        /// <summary>
        /// Deregister Jws implementation. Subsequent calls to Decode/Encode for given alg will throw 'InvalidAlgorithmException'.
        /// Note: this method is not updating alg aliases. One should take care of it manually.
        /// </summary>
        public JwtSettings DeregisterJws(string alg)
        {
            //jwsAlgorithms.Remove(alg);

            //return this;
            throw new NotImplementedException("TODO");

        }

        /// <summary>
        /// Deregister Jwa implementation. Subsequent calls to Decode/Encode for given alg will throw 'InvalidAlgorithmException'.
        /// Note: this method is not updating alg aliases. One should take care of it manually.
        /// </summary>
        public JwtSettings DeregisterJwa(JweAlgorithm alg)
        {
            keyAlgorithms.Remove(keyAlgorithmsHeaderValue[alg]);

            return this;           
        }

        /// <summary>
        /// Deregister Jwa implementation. Subsequent calls to Decode/Encode for given alg will throw 'InvalidAlgorithmException'.
        /// Note: this method is not updating alg aliases. One should take care of it manually.
        /// </summary>
        public JwtSettings DeregisterJwa(string alg)
        {
            keyAlgorithms.Remove(alg);

            return this;
        }

        /// <summary>
        /// Deregister Jwe implementation. Subsequent calls to Decode/Encode for given alg will throw 'InvalidAlgorithmException'.
        /// Note: this method is not updating alg aliases. One should take care of it manually.
        /// </summary>
        public JwtSettings DeregisterJwe(JweEncryption alg)
        {
            encAlgorithms.Remove(encAlgorithmsHeaderValue[alg]);

            return this;
        }

        /// <summary>
        /// Deregister Jwe implementation. Subsequent calls to Decode/Encode for given alg will throw 'InvalidAlgorithmException'.
        /// Note: this method is not updating alg aliases. One should take care of it manually.
        /// </summary>
        public JwtSettings DeregisterJwe(string alg)
        {
            //encAlgorithms.Remove(alg);

            //return this;

            throw new NotImplementedException("TODO");
        }

        /// <summary>
        /// Deregister compression implementation. Subsequent calls to Decode/Encode for given alg will throw 'InvalidAlgorithmException'.
        /// Note: this method is not updating alg aliases. One should take care of it manually.
        /// </summary>
        public JwtSettings DeregisterCompression(JweCompression alg)
        {
            compressionAlgorithms.Remove(alg);

            return this;
        }

        /// <summary>
        /// Deregister compression implementation. Subsequent calls to Decode/Encode for given alg will throw 'InvalidAlgorithmException'.
        /// Note: this method is not updating alg aliases. One should take care of it manually.
        /// </summary>
        public JwtSettings DeregisterCompression(string alg)
        {
            //compressionAlgorithms.Remove(alg);

            //return this;
            throw new NotImplementedException("TODO");
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
        public IJweAlgorithm Jwe(string alg)
        {
            IJweAlgorithm impl;
            return encAlgorithms.TryGetValue(alg, out impl) ? impl : null;
        }

        public static string JweHeaderValue(JweEncryption algorithm)
        {
            return encAlgorithmsHeaderValue[algorithm];
        }

        public IJweAlgorithm JweAlgorithmFromHeader(string headerValue)
        {
            foreach (var pair in encAlgorithmsHeaderValue)
            {
                if (pair.Value.Equals(headerValue))
                {
                    return Jwe(headerValue);
                }
            }

            //try alias
            JweEncryption aliasMatch;

            if (encAlgorithmsAliases.TryGetValue(headerValue, out aliasMatch))
            {
                // TODO: simplify with string -> string alias mapping
                return Jwe(JwtSettings.JweHeaderValue(aliasMatch));
            }
            throw new InvalidAlgorithmException(string.Format("JWE algorithm is not supported: {0}", headerValue));
        }

        //JWA algorithm
        public IKeyManagement Jwa(string alg)
        {
            IKeyManagement impl;
            return keyAlgorithms.TryGetValue(alg, out impl) ? impl : null;
        }

        /// <summary>
        /// TODO: Instead of JWTSettings.JwaHeaderValue(...), should go to:
        /// JWT.Headers.Jwe(JweAlgorithm) and JWT.Headers.Enc(string)
        /// JWT.Headers.Jwa(JwaAlgorithm) and JWT.Headers.Alg(string)
        /// JWT.Headers.Jws(JwaAlgorithm) and JWT.Headers.Alg(string)
        /// JWT.Headers.Zip(JwaAlgorithm) and JWT.Headers.Zip(string)
        /// </summary>
        /// <param name="alg"></param>
        /// <returns></returns>
        public static string JwaHeaderValue(JweAlgorithm alg)
        {
            return keyAlgorithmsHeaderValue[alg];
        }

        public IKeyManagement JwaAlgorithmFromHeader(string headerValue)
        {
            foreach (var pair in keyAlgorithmsHeaderValue)
            {
                if (pair.Value.Equals(headerValue))
                {
                    return Jwa(headerValue);
                }
            }

            if (keyAlgorithms.ContainsKey(headerValue))
            {
                return Jwa(headerValue);
            }

            //try alias
            JweAlgorithm aliasMatch;
            if (keyAlgorithmsAliases.TryGetValue(headerValue, out aliasMatch))
            {
                return Jwa(JwtSettings.JwaHeaderValue(aliasMatch));
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

        public static string CompressionHeader(JweCompression value)
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
