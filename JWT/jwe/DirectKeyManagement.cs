using System.Collections.Generic;

namespace Jose
{
    public class DirectKeyManagement : IKeyManagement
    {
        public byte[] NewKey(int keyLength, object key, IDictionary<string, object> header)
        {
            return Ensure.Type<byte[]>(key, "DirectKeyManagement alg expectes key to be byte[] array.");
        }

        public byte[] Wrap(byte[] cek, object key, IDictionary<string, object> header)
        {
            return Arrays.Empty;
        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            Ensure.IsEmpty(encryptedCek, "DirectKeyManagement expects empty content encryption key.");

            return Ensure.Type<byte[]>(key, "DirectKeyManagement alg expectes key to be byte[] array.");
        }
    }
}