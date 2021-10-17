namespace Jose
{
    /// <summary>
    /// Contains various options affecting token encoding/decoding.
    /// </summary>
    public class JwtOptions
    {
        public static readonly JwtOptions Default = new JwtOptions { EncodePayload = true, DetachPayload = false };

        /// <summary>
        /// RFC 7797:  whether payload part should be base64 encoded (default) during
        /// token encoding (JWS only)
        /// </summary>
        public bool EncodePayload { get; set; } = true;

        /// <summary>
        /// Whether payload should NOT be included to the encoded token (JWS only).
        /// False by default (include payload)
        /// </summary>
        public bool DetachPayload { get; set; }
    }
}