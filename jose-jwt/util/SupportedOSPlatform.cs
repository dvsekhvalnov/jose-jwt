#if !NET

namespace System.Runtime.Versioning;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Property | AttributeTargets.Class)]
internal class SupportedOSPlatform : Attribute
{
    internal SupportedOSPlatform(string platformName)
    {
    }
}

#endif