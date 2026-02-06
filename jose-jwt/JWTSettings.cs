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
                keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES), new EcdhKeyManagementWin(true, new EcdhKeyManagementUnix(true)));
                keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES_A128KW), new EcdhKeyManagementWinWithAesKeyWrap(128, new AesKeyWrapManagement(128), new EcdhKeyManagementUnixWithAesKeyWrap(128, new AesKeyWrapManagement(128))));
                keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES_A192KW), new EcdhKeyManagementWinWithAesKeyWrap(192, new AesKeyWrapManagement(192), new EcdhKeyManagementUnixWithAesKeyWrap(192, new AesKeyWrapManagement(192))));
                keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES_A256KW), new EcdhKeyManagementWinWithAesKeyWrap(256, new AesKeyWrapManagement(256), new EcdhKeyManagementUnixWithAesKeyWrap(256, new AesKeyWrapManagement(256))));
            }
            else
            {
                keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES), new EcdhKeyManagementUnix(true));
                keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES_A128KW), new EcdhKeyManagementUnixWithAesKeyWrap(128, new AesKeyWrapManagement(128)));
                keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES_A192KW), new EcdhKeyManagementUnixWithAesKeyWrap(192, new AesKeyWrapManagement(192)));
                keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES_A256KW), new EcdhKeyManagementUnixWithAesKeyWrap(256, new AesKeyWrapManagement(256)));
            }
#else
            keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES), new EcdhKeyManagementWin(true, new EcdhKeyManagementUnix(true)));
            keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES_A128KW), new EcdhKeyManagementWinWithAesKeyWrap(128, new AesKeyWrapManagement(128), new EcdhKeyManagementUnixWithAesKeyWrap(128, new AesKeyWrapManagement(128))));
            keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES_A192KW), new EcdhKeyManagementWinWithAesKeyWrap(192, new AesKeyWrapManagement(192), new EcdhKeyManagementUnixWithAesKeyWrap(192, new AesKeyWrapManagement(192))));
            keyAlgorithms.Add(Headers.Jwa(JweAlgorithm.ECDH_ES_A256KW), new EcdhKeyManagementWinWithAesKeyWrap(256, new AesKeyWrapManagement(256), new EcdhKeyManagementUnixWithAesKeyWrap(256, new AesKeyWrapManagement(256))));
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

        // alias header -> key alg header
        private readonly Dictionary<string, JwsAlgorithm> jwsAlgorithmsAliases = new Dictionary<string, JwsAlgorithm>();

        private readonly Dictionary<string, IJweAlgorithm> encAlgorithms = new Dictionary<string, IJweAlgorithm>
        {
            { Headers.Jwe(JweEncryption.A128CBC_HS256), new AesCbcHmacEncryption(new HmacUsingSha("SHA256"), 256) },
            { Headers.Jwe(JweEncryption.A192CBC_HS384), new AesCbcHmacEncryption(new HmacUsingSha("SHA384"), 384) },
            { Headers.Jwe(JweEncryption.A256CBC_HS512), new AesCbcHmacEncryption(new HmacUsingSha("SHA512"), 512) },

            { Headers.Jwe(JweEncryption.A128GCM), new AesGcmEncryption(128) },
            { Headers.Jwe(JweEncryption.A192GCM), new AesGcmEncryption(192) },
            { Headers.Jwe(JweEncryption.A256GCM), new AesGcmEncryption(256) }
        };

        // alias header -> enc alg header
        private readonly Dictionary<string, string> encAlgorithmsAliases = new Dictionary<string, string>();

        private readonly Dictionary<string, IKeyManagement> keyAlgorithms = new Dictionary<string, IKeyManagement>
        {
            { Headers.Jwa(JweAlgorithm.RSA_OAEP), new RsaKeyManagement(true) },
            { Headers.Jwa(JweAlgorithm.RSA_OAEP_256), new RsaOaepKeyManagement(256) },
            { Headers.Jwa(JweAlgorithm.RSA_OAEP_384), new RsaOaepKeyManagement(384) },
            { Headers.Jwa(JweAlgorithm.RSA_OAEP_512), new RsaOaepKeyManagement(512) },
            { Headers.Jwa(JweAlgorithm.RSA1_5), new RsaKeyManagement(false) },
            { Headers.Jwa(JweAlgorithm.DIR), new DirectKeyManagement() },
            { Headers.Jwa(JweAlgorithm.A128KW), new AesKeyWrapManagement(128) },
            { Headers.Jwa(JweAlgorithm.A192KW), new AesKeyWrapManagement(192) },
            { Headers.Jwa(JweAlgorithm.A256KW), new AesKeyWrapManagement(256) },
            
            // PBKDF2 iterations limited per OWASP reccomendation: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
            { Headers.Jwa(JweAlgorithm.PBES2_HS256_A128KW), new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128), 310000) },
            { Headers.Jwa(JweAlgorithm.PBES2_HS384_A192KW), new Pbse2HmacShaKeyManagementWithAesKeyWrap(192, new AesKeyWrapManagement(192), 250000) },
            { Headers.Jwa(JweAlgorithm.PBES2_HS512_A256KW), new Pbse2HmacShaKeyManagementWithAesKeyWrap(256, new AesKeyWrapManagement(256), 120000) },

            { Headers.Jwa(JweAlgorithm.A128GCMKW), new AesGcmKeyWrapManagement(128) },
            { Headers.Jwa(JweAlgorithm.A192GCMKW), new AesGcmKeyWrapManagement(192) },
            { Headers.Jwa(JweAlgorithm.A256GCMKW), new AesGcmKeyWrapManagement(256) }
        };

        // alias header -> key alg header
        private readonly Dictionary<string, string> keyAlgorithmsAliases = new Dictionary<string, string>();

        private readonly Dictionary<string, ICompression> compressionAlgorithms = new Dictionary<string, ICompression>
        {
            { 
                // 250Kb limited decompression buffer
                Headers.Zip(JweCompression.DEF), new DeflateCompression(250 * 1024) 
            }
        };

        // alias header -> key alg header
        private readonly Dictionary<string, string> compressionAlgorithmsAliases = new Dictionary<string, string>();

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
            return RegisterJwa(Headers.Jwa(alg), impl);
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
            keyAlgorithmsAliases[alias] = Headers.Jwa(alg);
            return this;
        }

        /// <summary>
        /// Register Jwe implementation, will override existing one if any
        /// </summary>
        public JwtSettings RegisterJwe(JweEncryption alg, IJweAlgorithm impl)
        {
            return RegisterJwe(Headers.Jwe(alg), impl);            
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
            encAlgorithmsAliases[alias] = Headers.Jwe(alg);
            return this;
        }

        /// Register Compression implementation, will override existing one if any
        public JwtSettings RegisterCompression(JweCompression alg, ICompression impl)
        {
            return RegisterCompression(Headers.Zip(alg), impl);
        }

        public JwtSettings RegisterCompression(string alg, ICompression impl)
        {
            compressionAlgorithms[alg] = impl;
            return this;            
        }

        /// <summary>
        /// Register an alias for the "zip" header that should point to a standard compression algorithm
        /// </summary>
        public JwtSettings RegisterCompressionAlias(string alias, JweCompression alg)
        {
            compressionAlgorithmsAliases[alias] = Headers.Zip(alg);
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
            keyAlgorithms.Remove(Headers.Jwa(alg));

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
            encAlgorithms.Remove(Headers.Jwe(alg));

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
            return DeregisterCompression(Headers.Zip(alg));
        }

        /// <summary>
        /// Deregister compression implementation. Subsequent calls to Decode/Encode for given alg will throw 'InvalidAlgorithmException'.
        /// Note: this method is not updating alg aliases. One should take care of it manually.
        /// </summary>
        public JwtSettings DeregisterCompression(string alg)
        {
            compressionAlgorithms.Remove(alg);
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
        public IJweAlgorithm Jwe(string alg)
        {
            IJweAlgorithm impl;
            return encAlgorithms.TryGetValue(alg, out impl) ? impl : null;
        }

        public IJweAlgorithm JweAlgorithmFromHeader(string headerValue)
        {
            if (encAlgorithms.ContainsKey(headerValue))
            {
                return Jwe(headerValue);
            }

            //try alias
            string aliasMatch;

            if (encAlgorithmsAliases.TryGetValue(headerValue, out aliasMatch))
            {
                return Jwe(aliasMatch);
            }

            throw new InvalidAlgorithmException(string.Format("JWE algorithm is not supported: {0}", headerValue));
        }

        //JWA algorithm
        public IKeyManagement Jwa(string alg)
        {
            IKeyManagement impl;
            return keyAlgorithms.TryGetValue(alg, out impl) ? impl : null;
        }
   
        public IKeyManagement JwaAlgorithmFromHeader(string headerValue)
        {
            if (keyAlgorithms.ContainsKey(headerValue))
            {
                return Jwa(headerValue);
            }

            //try alias
            string aliasMatch;
            if (keyAlgorithmsAliases.TryGetValue(headerValue, out aliasMatch))
            {
                return Jwa(aliasMatch);
            }
            
            throw new InvalidAlgorithmException(string.Format("JWA algorithm is not supported: {0}.", headerValue));
        }

        //Compression
        public ICompression Compression(string alg)
        {
            return compressionAlgorithms[alg];
        }

        public ICompression CompressionAlgFromHeader(string header)
        {
            if (compressionAlgorithms.ContainsKey(header))
            {
                return Compression(header);
            }

            //try alias
            string aliasMatch;

            if (compressionAlgorithmsAliases.TryGetValue(header, out aliasMatch))
            {
                return Compression(aliasMatch);
            }

            throw new InvalidAlgorithmException(string.Format("Compression algorithm is not supported: {0}.", header));
        }
    }
}
