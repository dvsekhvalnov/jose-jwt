using System.IO;
using System.IO.Compression;

namespace Jose
{
    public class DeflateCompression : ICompression
    {
        private readonly long maxBufferSizeBytes;

        public DeflateCompression(long maxBufferSizeBytes)
        {
            this.maxBufferSizeBytes = maxBufferSizeBytes;
        }

        public byte[] Compress(byte[] plainText)
        {
            using (MemoryStream output = new MemoryStream())
            {
                using (DeflateStream gzip = new DeflateStream(output, CompressionMode.Compress))
                {
                    gzip.Write(plainText, 0, plainText.Length);
                }

                return output.ToArray();
            }
        }

        public byte[] Decompress(byte[] compressedText)
        {
            using (MemoryStream ms = new CappedMemoryStream(maxBufferSizeBytes))
            {
                using (MemoryStream compressedStream = new MemoryStream(compressedText))
                {
                    using (DeflateStream deflater = new DeflateStream(compressedStream, CompressionMode.Decompress))
                    {
                        deflater.CopyTo(ms);
                    }
                }

                return ms.ToArray();
            }
        }
    }
}