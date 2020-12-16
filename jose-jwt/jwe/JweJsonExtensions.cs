#if NETSTANDARD
namespace Jose.jwe
{
    internal static class JweJsonExtensions
    {
        internal static byte[] ProtectedHeaderBytes(this JweJson jwe) => Base64Url.Decode(jwe.Protected);
        
        internal static byte[] IvBytes(this JweJson jwe) => Base64Url.Decode(jwe.Iv);

        internal static byte[] AadBytes(this JweJson jwe) => Base64Url.Decode(jwe.Aad);

        internal static byte[] CiphertextBytes(this JweJson jwe) => Base64Url.Decode(jwe.Ciphertext);

        internal static byte[] TagBytes(this JweJson jwe) => Base64Url.Decode(jwe.Tag);
    }

    internal static class JweRecipientDtoExtensions
    {
        internal static byte[] EncryptedKeyBytes(this JweRecipientDto r) => Base64Url.Decode(r.EncryptedKey);
    }

    internal static class FlattenedJweJsonExtensions
    {
        internal static byte[] EncryptedKeyBytes(this FlattenedJweJson r) => Base64Url.Decode(r.EncryptedKey);       
    }
}
#endif //NETSTANDARD2_1