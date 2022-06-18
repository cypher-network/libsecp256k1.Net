﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Libsecp256k1Zkp.Net.Linking;
using static Libsecp256k1Zkp.Net.SchnorrNative;

namespace Libsecp256k1Zkp.Net
{
    public class Schnorr : IDisposable
    {
        private readonly Lazy<secp256k1_context_create> secp256k1_context_create;
        private readonly Lazy<secp256k1_schnorrsig_serialize> secp256k1_schnorrsig_serialize;
        private readonly Lazy<secp256k1_schnorrsig_parse> secp256k1_schnorrsig_parse;
        private readonly Lazy<secp256k1_schnorrsig_sign> secp256k1_schnorrsig_sign;
        private readonly Lazy<secp256k1_schnorrsig_verify> secp256k1_schnorrsig_verify;
        private readonly Lazy<secp256k1_scratch_space_create> secp256k1_scratch_space_create;
        private readonly Lazy<secp256k1_schnorrsig_verify_batch> secp256k1_schnorrsig_verify_batch;
        private readonly Lazy<secp256k1_context_destroy> secp256k1_context_destroy;
        
        private static readonly Lazy<string> _libPath = new(() => Resolver.Resolve(Constant.LIB));
        private static readonly Lazy<IntPtr> _libPtr = new(() => LoadNative.LoadLib(_libPath.Value));
        
        public IntPtr Context { get; private set; }

        public Schnorr()
        {
            secp256k1_context_create = Util.LazyDelegate<secp256k1_context_create>(_libPtr);
            secp256k1_schnorrsig_serialize = Util.LazyDelegate<secp256k1_schnorrsig_serialize>(_libPtr);
            secp256k1_schnorrsig_parse = Util.LazyDelegate<secp256k1_schnorrsig_parse>(_libPtr);
            secp256k1_schnorrsig_sign = Util.LazyDelegate<secp256k1_schnorrsig_sign>(_libPtr);
            secp256k1_schnorrsig_verify = Util.LazyDelegate<secp256k1_schnorrsig_verify>(_libPtr);
            secp256k1_scratch_space_create = Util.LazyDelegate<secp256k1_scratch_space_create>(_libPtr);
            secp256k1_schnorrsig_verify_batch = Util.LazyDelegate<secp256k1_schnorrsig_verify_batch>(_libPtr);
            secp256k1_context_destroy = Util.LazyDelegate<secp256k1_context_destroy>(_libPtr);
            
            Context = secp256k1_context_create.Value((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
        }

        /// <summary>
        /// Serialize a Schnorr signature.
        /// </summary>
        /// <param name="sig">Pointer to the signature.</param>
        /// <returns>Signature could be serialize, null otherwise.</returns>
        public byte[]? Serialize(byte[] sig)
        {
            if (sig.Length != Constant.SIGNATURE_SIZE)
                throw new ArgumentException($"{nameof(sig)} must be {Constant.SIGNATURE_SIZE} bytes");

            var out64 = new byte[Constant.SIGNATURE_SIZE];
            return secp256k1_schnorrsig_serialize.Value(Context, out64, sig) == 1 ? out64 : null;
        }

        /// <summary>
        /// Parse a Schnorr signature.
        /// </summary>
        /// <param name="sig">Pointer to the 64-byte signature to be parsed.</param>
        /// <returns>Signature could be parsed, null otherwise.</returns>
        public byte[]? Parse(byte[] sig)
        {
            if (sig.Length != Constant.SIGNATURE_SIZE)
                throw new ArgumentException($"{nameof(sig)} must be {Constant.SIGNATURE_SIZE} bytes");

            var out64 = new byte[Constant.SIGNATURE_SIZE];
            return secp256k1_schnorrsig_parse.Value(Context, out64, sig) == 1 ? out64 : null;
        }

        /// <summary>
        /// Create a Schnorr signature.
        /// </summary>
        /// <param name="msg32">The 32-byte message hash being signed.</param>
        /// <param name="seckey">The 32-byte secret key.</param>
        /// <returns>Signature if successfully. Otherwaise null.</returns>
        public byte[]? Sign(byte[] msg32, byte[] seckey)
        {
            if (msg32.Length != Constant.MESSAGE_SIZE)
                throw new ArgumentException($"{nameof(msg32)} must be {Constant.MESSAGE_SIZE} bytes");

            if (seckey.Length != Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(seckey)} must be {Constant.SECRET_KEY_SIZE} bytes");

            int nonce_is_negated = 0;
            var sigOut = new byte[Constant.SIGNATURE_SIZE];
            return secp256k1_schnorrsig_sign.Value(Context, sigOut, ref nonce_is_negated, msg32, seckey, IntPtr.Zero, (IntPtr)null) == 1 ? sigOut : null;
        }

        /// <summary>
        /// Verify a Schnorr signature.
        /// </summary>
        /// <param name="sig">The signature being verified.</param>
        /// <param name="msg32">The 32-byte message hash being verified.</param>
        /// <param name="pubkey">The public key to verify with.</param>
        /// <returns>True if correct signature. Otherwise Fasle.</returns>
        public bool Verify(byte[] sig, byte[] msg32, byte[] pubkey)
        {
            if (sig.Length != Constant.SIGNATURE_SIZE)
                throw new ArgumentException($"{nameof(sig)} must be {Constant.SIGNATURE_SIZE} bytes");

            if (msg32.Length != Constant.MESSAGE_SIZE)
                throw new ArgumentException($"{nameof(msg32)} must be {Constant.MESSAGE_SIZE} bytes");

            if (pubkey.Length != Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(pubkey)} must be {Constant.PUBLIC_KEY_SIZE} bytes");

            return secp256k1_schnorrsig_verify.Value(Context, sig, msg32, pubkey) == 1;
        }

        /// <summary>
        /// Verifies a set of Schnorr signatures.
        /// </summary>
        /// <param name="sigs">Array of signatures.</param>
        /// <param name="msgs32">Array of messages.</param>
        /// <param name="pubKeys">Array of public keys.</param>
        /// <returns></returns>
        public bool VerifyBatch(IEnumerable<byte[]> sigs, IEnumerable<byte[]> msgs32, IEnumerable<byte[]> pubKeys)
        {
            if (sigs?.Any() != true || msgs32?.Any() != true || pubKeys?.Any() != true)
                return false;

            var i = 0;
            var signatures = new IntPtr[sigs.Count()];
            var messages = new IntPtr[msgs32.Count()];
            var publicKeys = new IntPtr[pubKeys.Count()];
            var scratch = secp256k1_scratch_space_create.Value(Context, Constant.SCRATCH_SPACE_SIZE);

            sigs.ToList().ForEach(s =>
            {
                if (s.Length < Constant.SIGNATURE_SIZE)
                    return;

                var ptr = Marshal.AllocHGlobal(s.Length);
                Marshal.Copy(s, 0, ptr, s.Length);
                signatures[i] = ptr;
                i++;
            });
            i = 0;
            msgs32.ToList().ForEach(m =>
            {
                if (m.Length < Constant.MESSAGE_SIZE)
                    return;

                var ptr = Marshal.AllocHGlobal(m.Length);
                Marshal.Copy(m, 0, ptr, m.Length);
                messages[i] = ptr;
                i++;
            });
            i = 0;
            pubKeys.ToList().ForEach(p =>
            {
                if (p.Length < Constant.PUBLIC_KEY_SIZE)
                    return;

                var ptr = Marshal.AllocHGlobal(p.Length);
                Marshal.Copy(p, 0, ptr, p.Length);
                publicKeys[i] = ptr;
                i++;
            });

            return secp256k1_schnorrsig_verify_batch.Value(Context, scratch, signatures, messages, publicKeys, (uint)signatures.Length) == 1;
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
