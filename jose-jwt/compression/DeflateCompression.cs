using System;
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
            byte[] buffer = new byte[maxBufferSizeBytes];

            try
            {
                using (MemoryStream ms = new MemoryStream(buffer))
                {
                    using (MemoryStream compressedStream = new MemoryStream(compressedText))
                    {
                        using (DeflateStream deflater = new DeflateStream(compressedStream, CompressionMode.Decompress))
                        {
                            deflater.CopyTo(ms);
                        }
                    }

                    return Arrays.Truncate(ms.ToArray(), ms.Position);
                }
            }
            catch(NotSupportedException e)
            {
                throw new JoseException("Unable to deflate compressed payload, most likely exceeded decompression buffer size.", e);
            }
        }
    }
}