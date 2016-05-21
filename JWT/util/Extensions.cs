using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Jose
{
#if NET35
    public static class Extensions
    {
        public static void CopyTo(this Stream input, Stream output)
        {
            var buffer = new byte[1024];
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, read);
            }
        }
    }
#endif
}
