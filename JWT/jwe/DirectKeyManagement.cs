namespace Jose
{
    public class DirectKeyManagement : IKeyManagement
    {
        public byte[] NewKey(int keyLength, object key)
        {
            var sharedKey = Ensure.Type<byte[]>(key, "DirectKeyManagement alg expectes key to be byte[] array.");

            return sharedKey;
        }

        public byte[] Wrap(byte[] cek, object key)
        {            
            var sharedKey = Ensure.Type<byte[]>(key, "DirectKeyManagement alg expectes key to be byte[] array.");

            return Arrays.Empty;
        }

        public byte[] Unwrap(byte[] encryptedCek, object key)
        {
            Ensure.IsEmpty(encryptedCek, "DirectKeyManagement expects empty content encryption key.");

            var sharedKey = Ensure.Type<byte[]>(key, "DirectKeyManagement alg expectes key to be byte[] array.");

            return sharedKey;

        }
    }
}