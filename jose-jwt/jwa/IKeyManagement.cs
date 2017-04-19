using System.Collections.Generic;

namespace Jose
{
    public interface IKeyManagement
    {
        /// <summary>
        /// Generates anew Content Jwe Key (CEK) and wraps it via provided management key (Key-Jwe-Key)
        /// </summary>
        /// <param name="cekSizeBits">Length of key to generate (CEK) (bits).</param>
        /// <param name="key">management key (KEK)</param>
        /// <param name="header">JWT headers, dictionary can be mutated as part of call (e.g. keys added, e.t.c)</param>
        /// <returns>2 byte[] arrays: [0]=plain CEK, [1]=encrypted CEK</returns>
        byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header);

        /// <summary>
        /// Unwraps protected CEK using provided management key
        /// </summary>
        /// <param name="encryptedCek">wrapped (encrypted) CEK</param>
        /// <param name="key">management key (KEK) used to protected CEK</param>
        /// <param name="cekSizeBits">required unwrapped bit CEK size</param>
        /// <param name="header">JWT headers</param>
        /// <returns>unwapped (decrypted) CEK</returns>
        byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header);
    }
}