using System;
using System.Collections.Generic;
using System.IO;

namespace Jose
{
    // Concatenates multiple streams into one logical stream
    public class ConcatenatedStream : Stream
    {
        private readonly List<Stream> streams;
        private readonly Stream keepOpen; // stream we should NOT dispose
        private int index;
        private Stream current;

        public ConcatenatedStream(IEnumerable<Stream> streams, Stream keepOpen = null)
        {
            this.streams = new List<Stream>(streams);
            this.keepOpen = keepOpen;
            index = 0;
            current = this.streams.Count > 0 ? this.streams[0] : null;
        }

        private void MoveNextStream()
        {
            index++;
            current = index < streams.Count ? streams[index] : null;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (current == null) return 0;

            int read = current.Read(buffer, offset, count);
            if (read == 0)
            {
                MoveNextStream();
                return Read(buffer, offset, count);
            }
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                foreach (var s in streams)
                {
                    if (s != keepOpen)
                        s.Dispose();
                }
            }
            base.Dispose(disposing);
        }
    }
}