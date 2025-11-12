using System.IO;

namespace Jose
{
    public interface IJwsAlgorithm
    {
        byte[] Sign(Stream securedInput, object key);
        bool Verify(byte[] signature, Stream securedInput, object key);
    }
}