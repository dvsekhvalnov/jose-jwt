using System.IO;

namespace Jose
{
    public class Plaintext : IJwsAlgorithm
    {
        public byte[] Sign(Stream securedInput, object key)
        {
            return Arrays.Empty;
        }

        public bool Verify(byte[] signature, Stream securedInput, object key)
        {
            Ensure.IsNull(key, "Plaintext alg expects key to be null.");

            return signature.Length == 0;
        }
    }
}