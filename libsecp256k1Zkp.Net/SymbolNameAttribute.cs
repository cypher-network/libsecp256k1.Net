using System;

namespace Libsecp256k1Zkp.Net
{
    internal class SymbolNameAttribute : Attribute
    {
        public readonly string Name;

        public SymbolNameAttribute(string name)
        {
            Name = name;
        }
    }
}