using System;
using System.Linq;

namespace Jose
{
    public static class Der
    {
        /// <summary>
        /// Convert the concatenation of ECDSA signature point (R,S), also known as IEEE P1363, into DER ASN.1 encoding.
        /// </summary>
        /// <remarks>      
        /// Original code ported from jose4j project <see href="https://bitbucket.org/b_c/jose4j/src/f7c6da83b7f8097be7d3391b4eca9a7dec4e765f/src/main/java/org/jose4j/jws/EcdsaUsingShaAlgorithm.java#lines-119" />
        /// Which is derived from the Apache Santuario XML Security library's SignatureECDS implementation <see href=".http://santuario.apache.org/""/>        
        /// </remarks>
        public static byte[] ToASN1(byte[] concatenatedSignatureBytes)
        {
            var concatenatedSignatureSignedBytes = concatenatedSignatureBytes.Select(b => unchecked((sbyte)b)).ToArray();
            int rawLen = concatenatedSignatureSignedBytes.Length/2;

            int i;

            for (i = rawLen; (i > 0) && (concatenatedSignatureSignedBytes[rawLen - i] == 0); i--);

            int j = i;

            if (concatenatedSignatureSignedBytes[rawLen - i] < 0)
            {
                j += 1;
            }

            int k;

            for (k = rawLen; (k > 0) && (concatenatedSignatureSignedBytes[2*rawLen - k] == 0); k--);

            int l = k;

            if (concatenatedSignatureSignedBytes[2*rawLen - k] < 0)
            {
                l += 1;
            }

            int len = 2 + j + 2 + l;
            if (len > 255)
            {
                throw new Exception("Invalid format of ECDSA signature");
            }
            int offset;
            byte[] derEncodedSignatureBytes;
            if (len < 128)
            {
                derEncodedSignatureBytes = new byte[2 + 2 + j + 2 + l];
                offset = 1;
            }
            else
            {
                derEncodedSignatureBytes = new byte[3 + 2 + j + 2 + l];
                derEncodedSignatureBytes[1] = (byte) 0x81;
                offset = 2;
            }

            derEncodedSignatureBytes[0] = 48;
            derEncodedSignatureBytes[offset++] = (byte) len;
            derEncodedSignatureBytes[offset++] = 2;
            derEncodedSignatureBytes[offset++] = (byte) j;

            Buffer.BlockCopy(concatenatedSignatureSignedBytes, rawLen - i, derEncodedSignatureBytes, (offset + j) - i, i);

            offset += j;

            derEncodedSignatureBytes[offset++] = 2;
            derEncodedSignatureBytes[offset++] = (byte) l;

            Buffer.BlockCopy(concatenatedSignatureSignedBytes, 2*rawLen - k, derEncodedSignatureBytes, (offset + l) - k, k);

            return derEncodedSignatureBytes;
        }

        /// <summary>
        /// Convert the DER ASN.1 encoded ECDSA signature point (R,S) into a concatenation of R and S, also known as IEEE P1363.
        /// </summary>
        /// <remarks>      
        /// Original code ported from jose4j project <see href="https://bitbucket.org/b_c/jose4j/src/f7c6da83b7f8097be7d3391b4eca9a7dec4e765f/src/main/java/org/jose4j/jws/EcdsaUsingShaAlgorithm.java#lines-119" />
        /// Which is derived from the Apache Santuario XML Security library's SignatureECDS implementation <see href=".http://santuario.apache.org/""/>        
        /// </remarks>

        public static byte[] ToP1363(byte[] derEncodedBytes)
        {
            const int OUTPUT_LENGTH = 64;
            var derEncodedUnsignedBytes = derEncodedBytes.Select(b => unchecked((sbyte)b)).ToArray();
            if (derEncodedUnsignedBytes.Length < 8 || derEncodedUnsignedBytes[0] != 48)
            {
                throw new Exception("Invalid format of ECDSA signature");
            }

            int offset;
            if (derEncodedUnsignedBytes[1] > 0)
            {
                offset = 2;
            }
            else if (derEncodedUnsignedBytes[1] == unchecked((sbyte) 0x81))
            {
                offset = 3;
            }
            else
            {
                throw new Exception("Invalid format of ECDSA signature");
            }

            var rLength = derEncodedUnsignedBytes[offset + 1];

            int i;
            for (i = rLength; (i > 0) && (derEncodedUnsignedBytes[(offset + 2 + rLength) - i] == 0); i--);

            var sLength = derEncodedUnsignedBytes[offset + 2 + rLength + 1];

            int j;
            for (j = sLength; (j > 0) && (derEncodedUnsignedBytes[(offset + 2 + rLength + 2 + sLength) - j] == 0); j--);

            int rawLen = Math.Max(i, j);
            rawLen = Math.Max(rawLen, OUTPUT_LENGTH/2);

            if ((derEncodedUnsignedBytes[offset - 1] & 0xff) != derEncodedUnsignedBytes.Length - offset
                || (derEncodedUnsignedBytes[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
                || derEncodedUnsignedBytes[offset] != 2
                || derEncodedUnsignedBytes[offset + 2 + rLength] != 2)
            {
                throw new Exception("Invalid format of ECDSA signature");
            }
            
            byte[] concatenatedSignatureBytes = new byte[2*rawLen];

            Buffer.BlockCopy(derEncodedUnsignedBytes, (offset + 2 + rLength) - i, concatenatedSignatureBytes, rawLen - i, i);
            Buffer.BlockCopy(derEncodedUnsignedBytes, (offset + 2 + rLength + 2 + sLength) - j, concatenatedSignatureBytes, 2*rawLen - j, j);

            return concatenatedSignatureBytes;
        }
    }
}