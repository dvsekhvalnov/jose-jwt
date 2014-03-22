namespace Jose
{
    public class Plaintext:IJwsAlgorithm
    {
        public byte[] Sign(byte[] securedInput, object key)
        {
            return Arrays.Empty;
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
            Ensure.IsNull(key, "Plaintext alg expectes key to be null.");

            return signature.Length == 0;
        }
    }
}