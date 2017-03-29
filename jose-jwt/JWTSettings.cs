using Jose.jwe;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Jose
{
    /// <summary>
    /// JWT settings object.  JWT has a global DefaultSettings instance that can be used to set global defaults.  Additionally,
    /// every method in JWT supports adding an optional settings parameter to override the default settings just for that call.
    /// </summary>
    public class JWTSettings
    {
        private Dictionary<JwsAlgorithm, IJwsAlgorithm> hashAlgorithms = new Dictionary<JwsAlgorithm, IJwsAlgorithm>
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
#elif NETSTANDARD1_4 || NET461
                { JwsAlgorithm.ES256, new Jose.netstandard1_4.EcdsaUsingSha(256) },
                { JwsAlgorithm.ES384, new Jose.netstandard1_4.EcdsaUsingSha(384) },
                { JwsAlgorithm.ES512, new Jose.netstandard1_4.EcdsaUsingSha(521) }
#endif
            };

        private Dictionary<JweEncryption, IJweAlgorithm> encAlgorithms = new Dictionary<JweEncryption, IJweAlgorithm>
            {
                { JweEncryption.A128CBC_HS256, new AesCbcHmacEncryption(new HmacUsingSha("SHA256"), 256) },
                { JweEncryption.A192CBC_HS384, new AesCbcHmacEncryption(new HmacUsingSha("SHA384"), 384) },
                { JweEncryption.A256CBC_HS512, new AesCbcHmacEncryption(new HmacUsingSha("SHA512"), 512) },

                { JweEncryption.A128GCM, new AesGcmEncryption(128) },
                { JweEncryption.A192GCM, new AesGcmEncryption(192) },
                { JweEncryption.A256GCM, new AesGcmEncryption(256) }
            };

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

        private Dictionary<JweCompression, ICompression> compressionAlgorithms = new Dictionary<JweCompression, ICompression>
            {
                { JweCompression.DEF, new DeflateCompression() }
            };

#if NET40 || NET461
        private IJsonMapper jsMapper = new JSSerializerMapper();
#elif NETSTANDARD1_4
        private IJsonMapper jsMapper = new NewtonsoftMapper();
#endif


        public Dictionary<JwsAlgorithm, IJwsAlgorithm> HashAlgorithms
        {
            get { return hashAlgorithms; }
        }

        public Dictionary<JweEncryption, IJweAlgorithm> EncAlgorithms
        {
            get { return encAlgorithms; }
        }

        public Dictionary<JweAlgorithm, IKeyManagement> KeyAlgorithms
        {
            get { return keyAlgorithms; }
        }

        public Dictionary<JweCompression, ICompression> CompressionAlgorithms
        {
            get { return compressionAlgorithms; }
        }

        public IJsonMapper JsonMapper
        {
            get { return jsMapper; }
            set { jsMapper = value; }
        }
    }
}
