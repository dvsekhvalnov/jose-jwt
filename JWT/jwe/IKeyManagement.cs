using System.Collections.Generic;

namespace Jose
{
    public interface IKeyManagement
    {
        /// <summary>
        /// Generates new Content Encryption Key (CEK)
        /// </summary>
        /// <param name="keyLength">Length of key to generate (bits).</param>
        /// <param name="key">management key</param>
        /// <param name="header">JWT headers, dictionary can be mutated as part of call (e.g. keys added, e.t.c)</param>
        /// <returns></returns>
        byte[] NewKey(int keyLength, object key, IDictionary<string, object> header);

        /// <summary>
        /// Wraps CEK for transmission, usually encryps in some form.
        /// </summary>
        /// <param name="cek">plain encryption key</param>
        /// <param name="key">management key used to protect CEK</param>
        /// <returns>wrapped(encrypted) CEK</returns>
        byte[] Wrap(byte[] cek, object key);

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