using System.Reflection;

namespace Libsecp256k1Zkp.Net
{
    internal static class SymbolNameCache<TDelegate>
    {
        public static readonly string SymbolName;

        static SymbolNameCache()
        {
            SymbolName = typeof(TDelegate).GetCustomAttribute<SymbolNameAttribute>()!.Name;
        }
    }
}