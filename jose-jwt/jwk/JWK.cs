namespace Jose
{
    public class JWK
    {
        public const string Oct = "oct";
        public const string EC = "EC";
        public const string RSA = "RSA";
        public const string Signature = "sig";
        public const string Encryption = "enc";

        private byte[] octKey;

        // General
        public string Kty { get; set; }
        public string Use { get; set; }
        public string Alg { get; set; }
        public string Key { get; set; }
        public string[] KeyOps { get; }

        // Symmetric keys
        public string K { get; set; }

        public byte[] OctKey()
        {
            return octKey;
        }

        // Elliptic keys

        // Assymetric keys

        public JWK(byte[] key)
        {
            Kty = Oct;
            K = Base64Url.Encode(key);
            octKey = key;
        }
    }
}
