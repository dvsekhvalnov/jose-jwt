using System.Collections.Generic;

namespace Jose
{
    public class AesKeyWrapManagement : IKeyManagement
    {
        private readonly int kekLengthBits;

        public AesKeyWrapManagement(int kekLengthBits)
        {
            this.kekLengthBits = kekLengthBits;
        }

        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var sharedKey = Ensure.Type<byte[]>(key, "AesKeyWrap management algorithm expectes key to be byte[] array.");
            Ensure.BitSize(sharedKey, kekLengthBits, string.Format("AesKeyWrap management algorithm expected key of size {0} bits, but was given {1} bits", kekLengthBits, sharedKey.Length * 8L));

            var cek = Arrays.Random(cekSizeBits);
            var encryptedCek = AesKeyWrap.Wrap(cek, sharedKey);

            return new[] { cek, encryptedCek };
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            var sharedKey = Ensure.Type<byte[]>(key, "AesKeyWrap management algorithm expectes key to be byte[] array.");
            Ensure.BitSize(sharedKey, kekLengthBits, string.Format("AesKeyWrap management algorithm expected key of size {0} bits, but was given {1} bits", kekLengthBits, sharedKey.Length * 8L));

            return AesKeyWrap.Unwrap(encryptedCek, sharedKey);
        }
    }
}