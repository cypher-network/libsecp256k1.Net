using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using static System.Runtime.InteropServices.Architecture;
using static System.Runtime.InteropServices.RuntimeInformation;
using PlatInfo = System.ValueTuple<System.Runtime.InteropServices.OSPlatform, System.Runtime.InteropServices.Architecture>;

namespace Libsecp256k1Zkp.Net.Linking
{
    public static class Resolver
    {
        private static readonly Dictionary<PlatInfo, (string Prefix, string LibPrefix, string Extension)> PlatformPaths = new()
        {
            [(OSPlatform.Linux, X64)] = ("linux-x64", "lib", ".so"),
            [(OSPlatform.Linux, X86)] = ("linux-x86", "lib", ".so"),
            [(OSPlatform.Linux, Arm64)] = ("linux-arm64", "lib", ".so"),
            [(OSPlatform.Windows, X64)] = ("win-x64", "", ".dll"),
            [(OSPlatform.Windows, X86)] = ("win-x86", "", ".dll"),
            [(OSPlatform.Windows, Arm64)] = ("win-arm64", "", ".dll"),
            [(OSPlatform.OSX, X64)] = ("osx-x64", "lib", ".dylib"),
            [(OSPlatform.OSX, Arm64)] = ("osx-arm64", "lib", ".dylib"),
        };

        private static readonly OSPlatform[] SupportedPlatforms = { OSPlatform.Linux, OSPlatform.Windows, OSPlatform.OSX };
        private static string SupportedPlatformDescriptions() => string.Join("\n", PlatformPaths.Keys.Select(GetPlatformDesc));

        private static string GetPlatformDesc((OSPlatform OS, Architecture Arch) info) => $"{info.OS}; {info.Arch}";

        private static readonly OSPlatform CurrentOSPlatform = SupportedPlatforms.FirstOrDefault(IsOSPlatform);
        private static readonly PlatInfo CurrentPlatformInfo = (CurrentOSPlatform, ProcessArchitecture);
        private static readonly Lazy<string> CurrentPlatformDesc = new(() => GetPlatformDesc((CurrentOSPlatform, ProcessArchitecture)));

        private static readonly ConcurrentDictionary<PlatInfo, string> Cache = new();

        public static List<string> ExtraNativeLibSearchPaths = new();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="library"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static string Resolve(string library)
        {
            if (Cache.TryGetValue(CurrentPlatformInfo, out string? result))
            {
                return result;
            }
            if (!PlatformPaths.TryGetValue(CurrentPlatformInfo, out var platform))
            {
                throw new Exception(string.Join("\n", $"Unsupported platform: {CurrentPlatformDesc.Value}", "Must be one of:", SupportedPlatformDescriptions()));
            }

            var searchedPaths = new HashSet<string>();

            foreach (var containerDir in GetSearchLocations())
            {
                foreach (var libPath in SearchContainerPaths(containerDir, library, platform))
                {
                    if (!searchedPaths.Contains(libPath) && File.Exists(libPath))
                    {
                        Cache.TryAdd(CurrentPlatformInfo, libPath);
                        return libPath;
                    }
                    searchedPaths.Add(libPath);
                }
            }

            throw new Exception($"Platform can be supported but '{library}' lib not found for {CurrentPlatformDesc.Value} at: {Environment.NewLine}{string.Join(Environment.NewLine, searchedPaths)}");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        static IEnumerable<string> GetSearchLocations()
        {
            yield return Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            yield return Path.GetDirectoryName(Assembly.GetCallingAssembly().Location);
            yield return Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
            foreach(var extraPath in ExtraNativeLibSearchPaths)
            {
                yield return extraPath;
            }
            
            yield return Path.GetFullPath(
                Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                "../../content"));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="containerDir"></param>
        /// <param name="library"></param>
        /// <param name="platform"></param>
        /// <returns></returns>
        static IEnumerable<string> SearchContainerPaths(string containerDir, string library, (string Prefix, string LibPrefix, string Extension) platform)
        {
            foreach(var subDir in GetSearchSubDir(library, platform))
            {
                yield return Path.Combine(containerDir, subDir);
                yield return Path.Combine(containerDir, "publish", subDir);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="library"></param>
        /// <param name="platform"></param>
        /// <returns></returns>
        static IEnumerable<string> GetSearchSubDir(string library, (string Prefix, string LibPrefix, string Extension) platform)
        {
            string libFileName = platform.LibPrefix + library + platform.Extension;

            yield return libFileName;
            yield return Path.Combine(platform.Prefix, libFileName); ;
            yield return Path.Combine("native", platform.Prefix, libFileName); ;
            yield return Path.Combine("runtimes", platform.Prefix, "native", libFileName);

        }
    }
}