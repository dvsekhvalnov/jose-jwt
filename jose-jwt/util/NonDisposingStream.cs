using System;
using System.IO;

namespace Jose
{
    // Wrapper that prevents disposal of the underlying stream (used to protect caller-owned streams)
    internal class NonDisposingStream : Stream
    {
        private readonly Stream inner;

        public NonDisposingStream(Stream inner)
        {
            this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
            if (inner.CanSeek) inner.Position = 0; // ensure start position for consumers
        }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            // Intentionally do NOT dispose underlying stream; just flush if needed.
            if (disposing && inner.CanRead)
            {
                // no-op; caller manages lifecycle
            }
            base.Dispose(disposing);
        }
    }
}