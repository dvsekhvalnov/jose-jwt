namespace Jose.jwe
{
    internal static class JweJsonExtensions
    {
        internal static byte[] ProtectedHeaderBytes(this JweJson jwe) => Base64Url.Decode(jwe.Protected);

        internal static byte[] UnprotectedHeaderBytes(this JweJson jwe) => Base64Url.Decode(jwe.Unprotected);

        internal static byte[] IvBytes(this JweJson jwe) => Base64Url.Decode(jwe.Iv);

        internal static byte[] AadBytes(this JweJson jwe) => Base64Url.Decode(jwe.Aad);

        internal static byte[] CiphertextBytes(this JweJson jwe) => Base64Url.Decode(jwe.Ciphertext);

        internal static byte[] TagBytes(this JweJson jwe) => Base64Url.Decode(jwe.Tag);

        internal static void Validate(this JweJson j)
        {
            if (string.IsNullOrEmpty(j.Ciphertext))
            {
                throw new JoseException("'ciphertext' member must be present.");
            }
        }
    }

    internal static class JweRecipientDtoExtensions
    {
        internal static byte[] EncryptedKeyBytes(this JweRecipientDto r) => Base64Url.Decode(r.EncryptedKey);
    }

    internal static class FlattenedJweJsonExtensions
    {
        internal static byte[] EncryptedKeyBytes(this FlattenedJweJson r) => Base64Url.Decode(r.EncryptedKey);

        internal static void Validate(this FlattenedJweJson j)
        {
            ((JweJson)j).Validate();
        }
    }
}