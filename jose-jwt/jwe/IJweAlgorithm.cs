namespace Jose.jwe
{
    public interface IJweAlgorithm
    {
        /// <summary>
        /// Encrypts given plain text with Content Jwe Key (KEY)
        /// </summary>
        /// <param name="aad">Additional Authnetication Data according to JWE/JWA specs</param>
        /// <param name="plainText"></param>
        /// <param name="cek"></param>
        /// <returns>3 items array: [0]=init vector (IV), [1]=cipher text, [2]=auth tag</returns>
        byte[][] Encrypt(byte[] aad, byte[] plainText, byte[] cek);

        byte[] Decrypt(byte[] aad, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag);

        /// <summary>
        /// Returns key size for given algorithm
        /// </summary>
        int KeySize { get; }
    }
}