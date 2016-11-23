using System;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Jose.native
{
    public static class NCrypt
    {
        public const uint NTE_BAD_SIGNATURE = 0x80090006;

        public const uint KDF_ALGORITHMID = 8;
        public const uint KDF_PARTYUINFO = 9;
        public const uint KDF_PARTYVINFO = 10;
        public const uint KDF_SUPPPUBINFO = 11;
        public const uint KDF_SUPPPRIVINFO = 12;

    #if NET40 || NET461
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    #elif NETSTANDARD1_4
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    #endif
        public class NCryptBufferDesc : IDisposable
        {
            public uint ulVersion;
            public uint cBuffers;
            public IntPtr pBuffers;

            public NCryptBufferDesc(params NCryptBuffer[] buffers)
            {
                cBuffers = (uint) buffers.Length; //number of elements in pBuffer
                ulVersion = 0;

                pBuffers = Marshal.AllocHGlobal(buffers.Sum(buf => Marshal.SizeOf(buf)));

                int totalSizeBytes = 0;

                foreach (var buf in buffers)
                {
                    Marshal.StructureToPtr(buf, pBuffers+totalSizeBytes, false);
                    totalSizeBytes += Marshal.SizeOf(buf);
                }
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(pBuffers);
            }
        }

    #if NET40 || NET461
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    #elif NETSTANDARD1_4
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    #endif
        public class NCryptBuffer : IDisposable
        {
            public uint cbBuffer;
            public uint BufferType;
            public IntPtr pvBuffer;

            public NCryptBuffer(uint bufferType, string data)
            {
                BufferType = bufferType;
                cbBuffer = (uint)((data.Length * 2) + 2);
                pvBuffer = Marshal.AllocHGlobal(data.Length * 2);
                Marshal.Copy(data.ToCharArray(), 0, pvBuffer, data.Length);
            }

            public NCryptBuffer(uint bufferType, byte[] data)
            {
                BufferType = bufferType;
                cbBuffer = (uint)data.Length;
                pvBuffer = Marshal.AllocHGlobal(data.Length);
                Marshal.Copy(data, 0, pvBuffer, data.Length);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(pvBuffer);
            }
        }

    #if NET40 || NET461
        [DllImport("ncrypt.dll", CharSet = CharSet.Auto, SetLastError = true)]
    #elif NETSTANDARD1_4
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    #endif
        public static extern uint NCryptSecretAgreement(SafeNCryptKeyHandle hPrivKey,SafeNCryptKeyHandle hPublicKey,out SafeNCryptSecretHandle phSecret,uint flags);

    #if NET40 || NET461
        [DllImport("ncrypt.dll", CharSet = CharSet.Auto, SetLastError = true)]
    #elif NETSTANDARD1_4
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    #endif
        public static extern uint NCryptDeriveKey(SafeNCryptSecretHandle hSharedSecret,
                                                  string kdf,
                                                  NCryptBufferDesc parameterList,
                                                  byte[] derivedKey,
                                                  uint derivedKeyByteSize,
                                                  out uint result,
                                                  uint flags);

        [DllImport("ncrypt.dll")]
        internal static extern uint NCryptSignHash(SafeNCryptKeyHandle hKey,
                                                   ref BCrypt.BCRYPT_PSS_PADDING_INFO pPaddingInfo,
                                                   byte[] pbHashValue,
                                                   int cbHashValue,
                                                   byte[] pbSignature,
                                                   int cbSignature,
                                                   out uint pcbResult,
                                                   uint dwFlags);

        [DllImport("ncrypt.dll")]
        internal static extern uint NCryptVerifySignature(SafeNCryptKeyHandle hKey,
                                                          ref BCrypt.BCRYPT_PSS_PADDING_INFO pPaddingInfo,
                                                          byte[] pbHashValue,
                                                          int cbHashValue,
                                                          byte[] pbSignature,
                                                          int cbSignature,
                                                          uint dwFlags);

        [DllImport("ncrypt.dll")]
        internal static extern uint NCryptDecrypt(SafeNCryptKeyHandle hKey,
                                                  byte[] pbInput,
                                                  int cbInput,
                                                  ref BCrypt.BCRYPT_OAEP_PADDING_INFO pvPadding,
                                                  byte[] pbOutput,
                                                  uint cbOutput,
                                                  out uint pcbResult,
                                                  uint dwFlags);

        [DllImport("ncrypt.dll")]
        internal static extern uint NCryptEncrypt(SafeNCryptKeyHandle hKey,
                                                  byte[] pbInput,
                                                  int cbInput,
                                                  ref BCrypt.BCRYPT_OAEP_PADDING_INFO pvPadding,
                                                  byte[] pbOutput,
                                                  uint cbOutput,
                                                  out uint pcbResult,
                                                  uint dwFlags);
    }
}