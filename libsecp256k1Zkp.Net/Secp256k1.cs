using System;
using System.Security.Cryptography;
using Libsecp256k1Zkp.Net.Linking;
using static Libsecp256k1Zkp.Net.Secp256k1Native;

namespace Libsecp256k1Zkp.Net
{
    public class Secp256k1 : IDisposable
    {
        private readonly Lazy<secp256k1_context_create> secp256k1_context_create;
        private readonly Lazy<secp256k1_context_destroy> secp256k1_context_destroy;
        private readonly Lazy<secp256k1_ec_pubkey_create> secp256k1_ec_pubkey_create;
        private readonly Lazy<secp256k1_ec_seckey_verify> secp256k1_ec_seckey_verify;
        private readonly Lazy<secp256k1_ec_pubkey_serialize> secp256k1_ec_pubkey_serialize;
        private readonly Lazy<secp256k1_ec_pubkey_parse> secp256k1_ec_pubkey_parse;
        private readonly Lazy<secp256k1_ecdsa_sign> secp256k1_ecdsa_sign;
        private readonly Lazy<secp256k1_ecdsa_verify> secp256k1_ecdsa_verify;
        private readonly Lazy<secp256k1_ecdh> secp256k1_ecdh;
        private readonly Lazy<secp256k1_context_randomize> secp256k1_context_randomize;

        private static readonly Lazy<string> _libPath = new(() => Resolver.Resolve(Constant.LIB));
        private static readonly Lazy<IntPtr> _libPtr = new(() => LoadNative.LoadLib(_libPath.Value));

        public IntPtr Context { get; private set; }

        public Secp256k1()
        {
            secp256k1_context_create = Util.LazyDelegate<secp256k1_context_create>(_libPtr);
            secp256k1_ec_pubkey_create = Util.LazyDelegate<secp256k1_ec_pubkey_create>(_libPtr);
            secp256k1_ec_seckey_verify = Util.LazyDelegate<secp256k1_ec_seckey_verify>(_libPtr);
            secp256k1_ec_pubkey_serialize = Util.LazyDelegate<secp256k1_ec_pubkey_serialize>(_libPtr);
            secp256k1_context_destroy = Util.LazyDelegate<secp256k1_context_destroy>(_libPtr);
            secp256k1_ec_pubkey_parse = Util.LazyDelegate<secp256k1_ec_pubkey_parse>(_libPtr);
            secp256k1_ecdsa_verify = Util.LazyDelegate<secp256k1_ecdsa_verify>(_libPtr);
            secp256k1_ecdsa_sign = Util.LazyDelegate<secp256k1_ecdsa_sign>(_libPtr);
            secp256k1_ecdh = Util.LazyDelegate<secp256k1_ecdh>(_libPtr);
            secp256k1_context_randomize = Util.LazyDelegate<secp256k1_context_randomize>(_libPtr);
            
            Context = secp256k1_context_create.Value((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
        }
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="compressPublicKey"></param>
        /// <returns></returns>
        public KeyPair GenerateKeyPair(bool compressPublicKey = false)
        {
            var privateKey = CreatePrivateKey();
            var publicKey = CreatePublicKey(privateKey);
            if (compressPublicKey)
            {
                publicKey = SerializePublicKey(publicKey, Flags.SECP256K1_EC_COMPRESSED);
            }

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="seed"></param>
        /// <param name="compressPublicKey"></param>
        /// <returns></returns>
        public KeyPair? GenerateKeyPair(byte[] seed, bool compressPublicKey = false)
        {
            var sha256 = HashAlgorithm.Create("SHA-256");
            var privateKey = sha256?.ComputeHash(seed);
            if (privateKey == null) return null;
            var publicKey = CreatePublicKey(privateKey);
            if (compressPublicKey)
            {
                publicKey = SerializePublicKey(publicKey, Flags.SECP256K1_EC_COMPRESSED);
            }

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pubKey"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public byte[]? PubKeyParse(byte[] pubKey, int size)
        {
            if (pubKey.Length < Constant.PUBLIC_KEY_COMPRESSED_SIZE)
                throw new ArgumentException($"{nameof(pubKey)} must be {Constant.PUBLIC_KEY_COMPRESSED_SIZE} bytes");

            if (pubKey.Length > Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(pubKey)} must be {Constant.PUBLIC_KEY_SIZE} bytes");

            var parsedOut = new byte[size];
            return secp256k1_ec_pubkey_parse.Value(Context, parsedOut, pubKey, size) == 1 ? parsedOut : null;
        }

        /// <summary>
        /// Gets the secret key.
        /// </summary>
        /// <returns>The secret key.</returns>
        public byte[] CreatePrivateKey()
        {
            var key = new byte[32];
            var rnd = RandomNumberGenerator.Create();

            do { rnd.GetBytes(key); }
            while (!VerifySecKey(key));

            return key;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pubKey"></param>
        /// <param name="privKey"></param>
        /// <returns></returns>
        public byte[]? ECDH(byte[] pubKey, byte[] privKey)
        {
            if (pubKey.Length > Constant.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH)
                throw new ArgumentException($"{nameof(pubKey)} must be {Constant.PUBLIC_KEY_SIZE} bytes or {Constant.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH} bytes");

            if (privKey.Length != Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(privKey)} must be {Constant.SECRET_KEY_SIZE} bytes");

            var result = new byte[32];
            return secp256k1_ecdh.Value(Context, result, pubKey, privKey) == 1 ? result : null;
        }
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        public byte[] RandomSeed(int size = 16)
        {
            var random = RandomNumberGenerator.Create();
            var bytes = new byte[size];
            random.GetNonZeroBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public byte[]? Randomize32()
        {
            var seed32 = RandomSeed(32);
            return secp256k1_context_randomize.Value(Context, seed32) == 1 ? seed32 : null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="seckey"></param>
        /// <returns></returns>
        public byte[]? CreatePublicKey(byte[] seckey, bool compress = false)
        {
            if (seckey.Length != Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(seckey)} must be {Constant.SECRET_KEY_SIZE} bytes");
            
            var pubOut = new byte[64];
            if (secp256k1_ec_pubkey_create.Value(Context, pubOut, seckey) != 1) return null;
            return compress ? SerializePublicKey(pubOut, Flags.SECP256K1_EC_COMPRESSED) : pubOut;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pubKey"></param>
        /// <param name="flags"></param>
        /// <returns></returns>
        public byte[]? SerializePublicKey(byte[] pubKey, Flags flags = Flags.SECP256K1_EC_UNCOMPRESSED)
        {
            if (pubKey.Length > Constant.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH)
                throw new ArgumentException($"{nameof(pubKey)} must be {Constant.PUBLIC_KEY_SIZE} bytes or {Constant.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH} bytes");

            bool compressed = flags.HasFlag(Flags.SECP256K1_EC_COMPRESSED);
            int serializedPubKeyLength = compressed ? Constant.SERIALIZED_COMPRESSED_PUBKEY_LENGTH : Constant.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            uint newLength = (uint)serializedPubKeyLength;

            var outPub = new byte[serializedPubKeyLength];
            return secp256k1_ec_pubkey_serialize.Value(Context, outPub, ref newLength, pubKey, (uint)flags) == 1 ? outPub : null;
        }

        /// <summary>
        /// Sign the specified msg32 and seckey.
        /// </summary>
        /// <returns>The sign.</returns>
        /// <param name="msg32">Msg32.</param>
        /// <param name="seckey">Seckey.</param>
        public byte[]? Sign(byte[] msg32, byte[] seckey)
        {
            if (msg32.Length != Constant.MESSAGE_SIZE)
                throw new ArgumentException($"{nameof(msg32)} must be {Constant.MESSAGE_SIZE} bytes");

            if (seckey.Length != Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(seckey)} must be {Constant.SECRET_KEY_SIZE} bytes");

            var sigOut = new byte[64];
            return secp256k1_ecdsa_sign.Value(Context, sigOut, msg32, seckey, IntPtr.Zero, (IntPtr)null) == 1 ? sigOut : null;
        }

        /// <summary>
        /// Verify the specified sig, msg32 and pubkey.
        /// </summary>
        /// <returns>The verify.</returns>
        /// <param name="sig">Sig.</param>
        /// <param name="msg32">Msg32.</param>
        /// <param name="pubkey">Pubkey.</param>
        public bool Verify(byte[] sig, byte[] msg32, byte[] pubkey)
        {
            if (sig.Length != Constant.SIGNATURE_SIZE)
                throw new ArgumentException($"{nameof(sig)} must be {Constant.SIGNATURE_SIZE} bytes");

            if (msg32.Length != Constant.MESSAGE_SIZE)
                throw new ArgumentException($"{nameof(msg32)} must be {Constant.MESSAGE_SIZE} bytes");

            if (pubkey.Length < Constant.PUBLIC_KEY_COMPRESSED_SIZE)
                throw new ArgumentException($"{nameof(pubkey)} must be {Constant.PUBLIC_KEY_COMPRESSED_SIZE} bytes");

            if (pubkey.Length > Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(pubkey)} must be {Constant.PUBLIC_KEY_SIZE} bytes");

            return secp256k1_ecdsa_verify.Value(Context, sig, msg32, pubkey) == 1;
        }

        /// <summary>
        /// Verifies the sec key.
        /// </summary>
        /// <returns><c>true</c>, if sec key was verifyed, <c>false</c> otherwise.</returns>
        /// <param name="seckey">Seckey.</param>
        public bool VerifySecKey(byte[] seckey)
        {
            if (seckey.Length != Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(seckey)} must be {Constant.SECRET_KEY_SIZE} bytes");

            return secp256k1_ec_seckey_verify.Value(Context, seckey) == 1;
        }

        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            if (Context == IntPtr.Zero) return;
            secp256k1_context_destroy.Value(Context);
            Context = IntPtr.Zero;
        }
    }
}
