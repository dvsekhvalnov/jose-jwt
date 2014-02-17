using System;
using System.Security.Cryptography;
using System.Text;

namespace Json
{
    public class AesCbcHmac : IJweAlgorithm
    {
        private IJwsAlgorithm hashAlgorithm;

        private readonly int keyLength;

        public AesCbcHmac(IJwsAlgorithm hashAlgorithm, int keyLength)
        {
            this.hashAlgorithm = hashAlgorithm;
            this.keyLength = keyLength;
        }

        public byte[][] Encrypt(byte[] aad, byte[] plainText, byte[] cek)
        {
            Ensure.BitSize(cek, keyLength, string.Format("AES-CBC with HMAC algorithm expected key of size {0} bits, but was given {1} bits", keyLength, cek.Length * 8));

            byte[] hmacKey = Arrays.FirstHalf(cek);
            byte[] aesKey = Arrays.SecondHalf(cek);

            byte[] iv = Arrays.Random();                        

            byte[] cipherText = AES.Encrypt(plainText, aesKey, iv);

            byte[] authTag = ComputeAuthTag(aad, iv, cipherText, hmacKey);

            return new[] {iv, cipherText, authTag};
        }

        public byte[] Decrypt(byte[] aad, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag)
        {
            Ensure.BitSize(cek, keyLength, string.Format("AES-CBC with HMAC algorithm expected key of size {0} bits, but was given {1} bits", keyLength, cek.Length * 8));

            byte[] hmacKey = Arrays.FirstHalf(cek);
            byte[] aesKey = Arrays.SecondHalf(cek);

            // Check MAC
            byte[] expectedAuthTag = ComputeAuthTag(aad, iv, cipherText, hmacKey);

            if (!Arrays.ConstantTimeEquals(expectedAuthTag, authTag))
            {
                throw new SignatureVerificationException(string.Format("Invalid signature."));
            }

            return AES.Decrypt(cipherText, aesKey, iv);
        }

        public int KeySize
        {
            get { return keyLength; }
        }

        private byte[] ComputeAuthTag(byte[] aad, byte[] iv, byte[] cipherText, byte[] hmacKey)
        {
            byte[] al = Arrays.SixtyFourBitLength(aad);
            byte[] hmacInput = Arrays.Concat(aad, iv, cipherText, al);

            byte[] hmac = hashAlgorithm.Sign(hmacInput, hmacKey);

            return Arrays.FirstHalf(hmac);
        }

    }
}