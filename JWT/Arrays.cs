using System;
using System.Linq;
using System.Security.Cryptography;

namespace Json
{
    public class Arrays
    {
        public readonly static byte[] Empty=new byte[0];

        private static RNGCryptoServiceProvider rng;

        public static byte[] SixtyFourBitLength(byte[] aad)
        {
            int bitLength = aad.Length * 8;

            //when
            byte[] bytes = BitConverter.GetBytes((long)bitLength);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            return bytes;
        }

        public static byte[] FirstHalf(byte[] arr)
        {
            int halfIndex = arr.Length/2;

            byte[] result = new byte[halfIndex];

            Buffer.BlockCopy(arr, 0, result, 0, halfIndex);

            return result;
        }

        public static byte[] SecondHalf(byte[] arr)
        {
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
            Console.Out.Write("\n{0}({1} bytes): [",label+" ", arr.Length);

            foreach (var b in arr)
            {
                Console.Out.Write(b+",");
            }

            Console.Out.Write("]\n");
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
    }
}
