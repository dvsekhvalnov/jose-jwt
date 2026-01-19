#if NET40
using System;
using System.Security.Cryptography;

namespace Jose
{
    public class EcdsaUsingSha : IJwsAlgorithm
    {
        private readonly int keySize;

        public EcdsaUsingSha(int keySize)
        {
            this.keySize = keySize;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
            var privateKey = Ensure.Type<CngKey>(key, "EcdsaUsingSha alg expects key to be of CngKey type.");

            Ensure.BitSize(privateKey.KeySize, keySize, string.Format("ECDSA algorithm expected key of size {0} bits, but was given {1} bits", keySize, privateKey.KeySize));

            try
            {
                using (var signer = new ECDsaCng(privateKey))
                {
                    signer.HashAlgorithm = Hash;

                    return signer.SignData(securedInput);
                }
            }
            catch (CryptographicException e)
            {
                throw new JoseException("Unable to sign content.", e);
            }
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
            var publicKey = Ensure.Type<CngKey>(key, "EcdsaUsingSha alg expects key to be of CngKey type.");

            Ensure.BitSize(publicKey.KeySize, keySize, string.Format("ECDSA algorithm expected key of size {0} bits, but was given {1} bits", keySize, publicKey.KeySize));

            try
            {
                using (var signer = new ECDsaCng(publicKey))
                {
                    signer.HashAlgorithm = Hash;

                    return signer.VerifyData(securedInput, signature);
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
        }
        
        /// <summary>
        /// Convert the concatenation of R and S into DER encoding
        /// </summary>
        /// <remarks>
        /// The result of an ECDSA signature is the EC point (R, S), where R and S are unsigned (very large) integers.
        /// The JCA ECDSA signature implementation (sun.security.ec.ECDSASignature) produces and expects a DER encoding
        /// of R and S while JOSE/JWS wants R and S as a concatenated byte array. XML signatures (best I can tell) treats
        /// ECDSA similarly to JOSE and the code for the two methods that convert to and from DER and concatenated
        /// R and S was originally taken from org.apache.xml.security.algorithms.implementations.SignatureECDSA in the
        /// (Apache 2 licensed) Apache Santuario XML Security library. Some minor changes have been made to ensure the
        /// concatenated output left zero pads R & S to consistent length - i.e. the "octet sequence representations
        /// MUST NOT be shortened to omit any leading zero octets" per <see href="http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-25#section-3.4" />
        /// 
        /// Which seemed like a better idea than trying to write it myself or using sun.security.util.Der[Input/Output]Stream
        /// as sun.security.ec.ECDSASignature does or some other half-arsed approach.
        /// <see href="https://bitbucket.org/b_c/jose4j/src/f7c6da83b7f8097be7d3391b4eca9a7dec4e765f/src/main/java/org/jose4j/jws/EcdsaUsingShaAlgorithm.java#lines-119">
        /// Modified and used b_c/jose4j under Apache License Version 2.0, relicensed under MIT License (jose-jwt/LICENSE)
        /// </see>
        /// </remarks>
        public static byte[] ConvertConcatenatedToDer(byte[] concatenatedSignatureBytes)
        {
            int rawLen = concatenatedSignatureBytes.Length/2;

            int i;

            for (i = rawLen; (i > 0) && (concatenatedSignatureBytes[rawLen - i] == 0); i--);

            int j = i;

            if (concatenatedSignatureBytes[rawLen - i] < 0)
            {
                j += 1;
            }

            int k;

            for (k = rawLen; (k > 0) && (concatenatedSignatureBytes[2*rawLen - k] == 0); k--);

            int l = k;

            if (concatenatedSignatureBytes[2*rawLen - k] < 0)
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

            Array.Copy(concatenatedSignatureBytes, rawLen - i, derEncodedSignatureBytes, (offset + j) - i, i);

            offset += j;

            derEncodedSignatureBytes[offset++] = 2;
            derEncodedSignatureBytes[offset++] = (byte) l;

            Array.Copy(concatenatedSignatureBytes, 2*rawLen - k, derEncodedSignatureBytes, (offset + l) - k, k);

            return derEncodedSignatureBytes;
        }

        /// <summary>
        /// Convert the DER encoding of R and S into a concatenation of R and S
        /// </summary>
        /// <remarks>
        /// <see href="https://bitbucket.org/b_c/jose4j/src/f7c6da83b7f8097be7d3391b4eca9a7dec4e765f/src/main/java/org/jose4j/jws/EcdsaUsingShaAlgorithm.java#lines-119">
        /// Modified and used b_c/jose4j under Apache License Version 2.0, relicensed under MIT License (jose-jwt/LICENSE)
        /// </see>
        /// </remarks>
        public static byte[] ConvertDerToConcatenated(byte[] derEncodedBytes, int outputLength)
        {

            if (derEncodedBytes.Length < 8 || derEncodedBytes[0] != 48)
            {
                throw new Exception("Invalid format of ECDSA signature");
            }

            int offset;
            if (derEncodedBytes[1] > 0)
            {
                offset = 2;
            }
            else if (derEncodedBytes[1] == (byte) 0x81)
            {
                offset = 3;
            }
            else
            {
                throw new Exception("Invalid format of ECDSA signature");
            }

            byte rLength = derEncodedBytes[offset + 1];

            int i;
            for (i = rLength; (i > 0) && (derEncodedBytes[(offset + 2 + rLength) - i] == 0); i--);

            byte sLength = derEncodedBytes[offset + 2 + rLength + 1];

            int j;
            for (j = sLength; (j > 0) && (derEncodedBytes[(offset + 2 + rLength + 2 + sLength) - j] == 0); j--);

            int rawLen = Math.Max(i, j);
            rawLen = Math.Max(rawLen, outputLength/2);

            if ((derEncodedBytes[offset - 1] & 0xff) != derEncodedBytes.Length - offset
                || (derEncodedBytes[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
                || derEncodedBytes[offset] != 2
                || derEncodedBytes[offset + 2 + rLength] != 2)
            {
                throw new Exception("Invalid format of ECDSA signature");
            }
            
            byte[] concatenatedSignatureBytes = new byte[2*rawLen];

            Array.Copy(derEncodedBytes, (offset + 2 + rLength) - i, concatenatedSignatureBytes, rawLen - i, i);
            Array.Copy(derEncodedBytes, (offset + 2 + rLength + 2 + sLength) - j, concatenatedSignatureBytes, 2*rawLen - j, j);

            return concatenatedSignatureBytes;
        }

        protected CngAlgorithm Hash
        {
            get
            {
                switch (keySize)
                {
                    case 256:
                        return CngAlgorithm.Sha256;
                    case 384:
                        return CngAlgorithm.Sha384;
                    case 521:
                        return CngAlgorithm.Sha512;
                    default:
                        throw new ArgumentException(string.Format("Unsupported key size: '{0} bytes'", keySize));
                }
            }
        }
    }
}
#endif