namespace Jose
{
    public interface IJwsAlgorithm
    {
        byte[] Sign(byte[] securedInput, object key);
        bool Verify(byte[] signature, byte[] securedInput, object key);
    }
}