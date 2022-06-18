using System;
using System.Runtime.InteropServices;

namespace Libsecp256k1Zkp.Net.Linking
{
    internal static class Linux
    {
        private const string LIBDL = "libdl.so.2";

        [DllImport(LIBDL)]
        public static extern IntPtr dlopen(string path, int flags);

        [DllImport(LIBDL)]
        public static extern int dlclose(IntPtr handle);

        [DllImport(LIBDL)]
        public static extern IntPtr dlerror();

        [DllImport(LIBDL)]
        public static extern IntPtr dlsym(IntPtr handle, string name);
    }
}