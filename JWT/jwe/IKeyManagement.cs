namespace Jose
{
    public interface IKeyManagement
    {
        /// <summary>
        /// Generates new Content Encryption Key (CEK)
        /// </summary>
        /// <param name="keyLength">Length of key to generate (bits).</param>
        /// <param name="key">management key</param>
        /// <returns></returns>
        byte[] NewKey(int keyLength, object key);

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
        /// <param name="key">management key used to protected CEK</param>
        /// <returns>unwapped (decrypted) CEK</returns>
        byte[] Unwrap(byte[] encryptedCek, object key);
    }
}