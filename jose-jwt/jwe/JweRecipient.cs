using System;
using System.Collections.Generic;

namespace Jose
{
    /// <summary>
    /// JWE Recipient object representation. Part of JWE token.
    /// </summary>
    public class JweRecipient
    {
        /// <summary>
        /// Constructs recipient for JWE decryption with encrypted CEK and headers
        /// </summary>
        /// <param name="encryptedCek">encrypted content encryption key</param>
        /// <param name="header">per recipient headers</param>
        public JweRecipient(byte[] encryptedCek, IDictionary<string, object> header)
        {
            EncryptedCek = encryptedCek;
            Header = header;
        }

        /// <summary>
        /// Constructs recipient for JWE encryption with desired KEK and key management algorithm
        /// </summary
        /// <param name="alg">algorithm to be used to encrypt the CEK (Content Encryption Key).</param>
        /// <param name="key">key for encrypting CEK (Content Encryption Key). Cannot be null.</param>
        public JweRecipient(JweAlgorithm alg, object key, IDictionary<string, object> header = null)
        {
            this.Alg = JwtSettings.JwaHeaderValue(alg);
            this.Key = key ?? throw new ArgumentNullException(nameof(key));
            this.Header = header;
        }

        public JweRecipient(string alg, object key, IDictionary<string, object> header = null)
        {
            this.Alg = alg;
            this.Key = key ?? throw new ArgumentNullException(nameof(key));
            this.Header = header;
        }

        /// <summary>
        /// Content key encryption algorithm
        /// </summary>
        public string Alg { get; }

        /// <summary>
        /// Key to encrypt content key (KEK)
        /// </summary>
        public object Key { get; }

        /// <summary>
        /// Encrypted content encryption key
        /// </summary>
        public byte[] EncryptedCek { get; }

        /// <summary>
        /// Per recipient headers
        /// </summary>
        public IDictionary<string, object> Header { get; }

        /// <summary>
        /// Effective headers (protected | unprotected | recipient), avaliable only in context of JWE token
        /// </summary>
        public IDictionary<string, object> JoseHeader { get; internal set; }
    }
}
