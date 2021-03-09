using System;
using System.Collections.Generic;

namespace Jose
{
    public class JweRecipient
    {
        public JweRecipient(byte[] encryptedCek, IDictionary<string, object> header)
        {
            EncryptedCek = encryptedCek;
            Header = header;
        }

        /// <summary
        /// A recipient for a Jwe
        /// </summary
        /// <param name="alg">algorithm to be used to encrypt the CEK (Content Encryption Key).</param>
        /// <param name="key">key for encrypting CEK (Content Encryption Key). Cannot be null.</param>
        public JweRecipient(JweAlgorithm alg, object key, IDictionary<string, object> header = null)
        {
            this.Alg = alg;
            this.Key = key ?? throw new ArgumentNullException(nameof(key));
            this.Header = header;
        }

        public JweAlgorithm Alg { get; }

        public object Key { get; }
        public byte[] EncryptedCek { get; }

        public IDictionary<string, object> Header { get; }
        public IDictionary<string, object> JoseHeader { get; internal set; }
    }
}
