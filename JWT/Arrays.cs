using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Jose
{
    public class Arrays
    {
        public readonly static byte[] Empty=new byte[0];

        private static RNGCryptoServiceProvider rng;

        public static byte[] SixtyFourBitLength(byte[] aad)
        {
            return LongToBytes(aad.Length * 8);
        }

        public static byte[] FirstHalf(byte[] arr)
        {
            Ensure.Divisible(arr.Length, 2, "Arrays.FirstHalf() expects even number of element in array.");

            int halfIndex = arr.Length/2;

            byte[] result = new byte[halfIndex];

            Buffer.BlockCopy(arr, 0, result, 0, halfIndex);

            return result;
        }

        public static byte[] SecondHalf(byte[] arr)
        {
            Ensure.Divisible(arr.Length, 2, "Arrays.SecondHalf() expects even number of element in array.");

            int halfIndex = arr.Length/2;

            byte[] result = new byte[halfIndex];

            Buffer.BlockCopy(arr, halfIndex, result, 0, halfIndex);

            return result;
        }

        public static byte[] Concat(params byte[][] arrays)
        {
            byte[] result = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;

            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }

            return result;
        }

        public static byte[][] Slice(byte[] array, int count)
        {
            Ensure.MinValue(count, 1, "Arrays.Slice() expects count to be above zero, but was {0}", count);
            Ensure.Divisible(array.Length, count, "Arrays.Slice() expects array length to be divisible by {0}", count);

            int sliceCount = array.Length / count;

            byte[][] result = new byte[sliceCount][];


            for (int i = 0; i < sliceCount; i++)
            {
                byte[] slice=new byte[count];
    
                Buffer.BlockCopy(array,i*count,slice,0,count);

                result[i] = slice;
            }

            return result;
        }

        public static byte[] Xor(byte[] left, long right)
        {
            Ensure.BitSize(left, 64, "Arrays.Xor(byte[], long) expects array size to be 8 bytes, but was {0}", left.Length);

            long _left = BytesToLong(left);
            return LongToBytes(_left ^ right);
        }

        public static bool ConstantTimeEquals(byte[] expected, byte[] actual)
        {
            if (expected == actual)
                return true;

            if (expected == null || actual == null)
                return false;

            if (expected.Length != actual.Length) 
                return false;

            bool equals = true;

            for (int i = 0; i < expected.Length; i++)
                if (expected[i] != actual[i])
                    equals = false;

            return equals;
        }

        public static void Dump(byte[] arr, string label = "")
        {
            var builder=new StringBuilder();
            builder.Append(string.Format("{0}({1} bytes): [", label+" ", arr.Length).Trim());

            foreach (var b in arr)
            {
                builder.Append(b);
                builder.Append(",");
            }

            builder.Remove(builder.Length - 1, 1);
            builder.Append("]\n");

            Console.Out.WriteLine(builder.ToString());
        }        

        public static byte[] Random(int sizeBits=128)
        {
            byte[] data = new byte[sizeBits / 8];

            RNG.GetBytes(data);

            return data;      
        }

        internal static RNGCryptoServiceProvider RNG
        {
            get { return rng ?? (rng = new RNGCryptoServiceProvider()); }
        }

        public static byte[] LongToBytes(long value)
        {
            ulong _value = (ulong) value;

            return BitConverter.IsLittleEndian 
                ? new[] { (byte)((_value >> 56) & 0xFF), (byte)((_value >> 48) & 0xFF), (byte)((_value >> 40) & 0xFF), (byte)((_value >> 32) & 0xFF), (byte)((_value >> 24) & 0xFF), (byte)((_value >> 16) & 0xFF), (byte)((_value >> 8) & 0xFF), (byte)(_value & 0xFF) } 
                : new[] { (byte)(_value & 0xFF), (byte)((_value >> 8) & 0xFF), (byte)((_value >> 16) & 0xFF), (byte)((_value >> 24) & 0xFF), (byte)((_value >> 32) & 0xFF), (byte)((_value >> 40) & 0xFF), (byte)((_value >> 48) & 0xFF) , (byte)((_value >> 56) & 0xFF) };
        }

        private static long BytesToLong(byte[] array)
        {
            long msb = BitConverter.IsLittleEndian 
                        ? (long)(array[0] << 24 | array[1] << 16 | array[2] << 8 | array[3]) << 32
                        : (long)(array[7] << 24 | array[6] << 16 | array[5] << 8 | array[4]) << 32;;

            long lsb = BitConverter.IsLittleEndian
                           ? (array[4] << 24 | array[5] << 16 | array[6] << 8 | array[7]) & 0x00000000ffffffff
                           : (array[3] << 24 | array[2] << 16 | array[1] << 8 | array[0]) & 0x00000000ffffffff;
            
            return msb | lsb;
        }

    }
}
