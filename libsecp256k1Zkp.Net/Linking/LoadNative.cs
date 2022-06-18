using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Libsecp256k1Zkp.Net.Linking
{
    internal class LoadNative
    {
        static readonly bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        static readonly bool IsMacOS = RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        static readonly bool IsLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="libPath"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static IntPtr LoadLib(string libPath)
        {
            IntPtr libPtr;
            if (IsLinux)
            {
                const int RTLD_NOW = 2;
                libPtr = Linux.dlopen(libPath, RTLD_NOW);
            }
            else if (IsWindows)
            {
                libPtr = Windows.LoadLibrary(libPath);
            }
            else if (IsMacOS)
            {
                const int RTLD_NOW = 2;
                libPtr = MacOS.dlopen(libPath, RTLD_NOW);
            }
            else
            {
                throw new Exception(
                    $"Unsupported platform: {RuntimeInformation.OSDescription}. The supported platforms are: {string.Join(", ", new[] { OSPlatform.Windows, OSPlatform.OSX, OSPlatform.Linux })}");
            }

            if (libPtr == IntPtr.Zero)
            {
                throw new Exception($"Library loading failed, file: {libPath}", GetLastError());
            }

            return libPtr;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="lib"></param>
        /// <exception cref="Exception"></exception>
        public static void CloseLibrary(IntPtr lib)
        {
            if (lib == IntPtr.Zero)
            {
                return;
            }

            if (IsLinux)
            {
                Linux.dlclose(lib);
            }
            else if (IsWindows)
            {
                Windows.FreeLibrary(lib);
            }
            else if (IsMacOS)
            {
                MacOS.dlclose(lib);
            }
            else
            {
                throw new Exception("Unsupported platform");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        static Exception GetLastError()
        {
            if (IsWindows)
            {
                return new Win32Exception(Marshal.GetLastWin32Error());
            }

            IntPtr errorPtr;
            if (IsLinux)
            {
                errorPtr = Linux.dlerror();
            }
            else if (IsMacOS)
            {
                errorPtr = MacOS.dlerror();
            }
            else
            {
                throw new Exception("Unsupported platform");
            }

            return errorPtr == IntPtr.Zero
                ? new Exception("Error information could not be found")
                : new Exception(Marshal.PtrToStringAnsi(errorPtr));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="libPtr"></param>
        /// <param name="symbolName"></param>
        /// <typeparam name="TDelegate"></typeparam>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static TDelegate GetDelegate<TDelegate>(IntPtr libPtr, string symbolName)
        {
            IntPtr functionPtr;
            if (IsLinux)
            {
                functionPtr = Linux.dlsym(libPtr, symbolName);
            }
            else if (IsWindows)
            {
                functionPtr = Windows.GetProcAddress(libPtr, symbolName);
            }
            else if (IsMacOS)
            {
                functionPtr = MacOS.dlsym(libPtr, symbolName);
            }
            else
            {
                throw new Exception("Unsupported platform");
            }

            if (functionPtr == IntPtr.Zero)
            {
                throw new Exception($"Library symbol failed, symbol: {symbolName}", GetLastError());
            }

            return Marshal.GetDelegateForFunctionPointer<TDelegate>(functionPtr);
        }
    }
}