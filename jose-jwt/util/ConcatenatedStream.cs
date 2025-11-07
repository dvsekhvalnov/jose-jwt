using System;
using System.Collections.Generic;
using System.IO;

namespace Jose
{
    // Concatenates multiple streams into one logical stream
    public class ConcatenatedStream : Stream
    {
        private readonly IEnumerator<Stream> streams;
        private Stream current;

        public ConcatenatedStream(IEnumerable<Stream> streams)
        {
            this.streams = streams.GetEnumerator();
            MoveNextStream();
        }

        private void MoveNextStream()
        {
            current?.Dispose();
            if (streams.MoveNext())
                current = streams.Current;
            else
                current = null;
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
                current?.Dispose();
                while (streams.MoveNext())
                    streams.Current.Dispose();
                streams.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}