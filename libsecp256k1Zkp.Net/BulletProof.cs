using System;
using System.Runtime.InteropServices;
using Libsecp256k1Zkp.Net.Linking;
using static Libsecp256k1Zkp.Net.BulletProofNative;

namespace Libsecp256k1Zkp.Net
{
    public class BulletProof : IDisposable
    {
        private readonly Lazy<secp256k1_context_create> secp256k1_context_create;
        private readonly Lazy<secp256k1_bulletproof_generators_create> secp256k1_bulletproof_generators_create;
        private readonly Lazy<secp256k1_scratch_space_create> secp256k1_scratch_space_create;
        private readonly Lazy<secp256k1_bulletproof_rangeproof_prove> secp256k1_bulletproof_rangeproof_prove;
        private readonly Lazy<secp256k1_scratch_space_destroy> secp256k1_scratch_space_destroy;
        private readonly Lazy<secp256k1_bulletproof_rangeproof_rewind> secp256k1_bulletproof_rangeproof_rewind;
        private readonly Lazy<secp256k1_bulletproof_rangeproof_verify> secp256k1_bulletproof_rangeproof_verify;
        private readonly Lazy<secp256k1_context_destroy> secp256k1_context_destroy;

        private static readonly Lazy<string> _libPath = new(() => Resolver.Resolve(Constant.LIB));
        private static readonly Lazy<IntPtr> _libPtr = new(() => LoadNative.LoadLib(_libPath.Value));

        public IntPtr Context { get; private set; }

        public BulletProof()
        {
            secp256k1_context_create = Util.LazyDelegate<secp256k1_context_create>(_libPtr);
            secp256k1_bulletproof_generators_create = Util.LazyDelegate<secp256k1_bulletproof_generators_create>(_libPtr);
            secp256k1_scratch_space_create = Util.LazyDelegate<secp256k1_scratch_space_create>(_libPtr);
            secp256k1_bulletproof_rangeproof_prove = Util.LazyDelegate<secp256k1_bulletproof_rangeproof_prove>(_libPtr);
            secp256k1_scratch_space_destroy = Util.LazyDelegate<secp256k1_scratch_space_destroy>(_libPtr);
            secp256k1_bulletproof_rangeproof_rewind = Util.LazyDelegate<secp256k1_bulletproof_rangeproof_rewind>(_libPtr);
            secp256k1_bulletproof_rangeproof_verify = Util.LazyDelegate<secp256k1_bulletproof_rangeproof_verify>(_libPtr);
            secp256k1_context_destroy = Util.LazyDelegate<secp256k1_context_destroy>(_libPtr);

            Context = secp256k1_context_create.Value((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public IntPtr Generators()
        {
            return secp256k1_bulletproof_generators_create.Value(Context, Constant.GENERATOR_G, 256);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="value"></param>
        /// <param name="blind"></param>
        /// <param name="nonce"></param>
        /// <param name="rewindNonce"></param>
        /// <param name="extraCommit"></param>
        /// <param name="msg"></param>
        /// <param name="mValue"></param>
        /// <returns></returns>
        public ProofStruct GenerateBulletProof(ulong value, byte[] blind, byte[] nonce, byte[] rewindNonce, byte[] extraCommit, byte[] msg, int mValue = 0)
        {
            byte[] proof = new byte[Constant.MAX_PROOF_SIZE];
            int plen = Constant.MAX_PROOF_SIZE;
            var extraCommitLen = extraCommit == null ? 0 : extraCommit.Length;
            byte[] tau_x = null;
            byte[] t_one = null;
            byte[] t_two = null;
            byte[] commits = null;

            var blinds = new IntPtr[1];

            IntPtr ptr = Marshal.AllocHGlobal(32);
            Marshal.Copy(blind, 0, ptr, blind.Length);
            blinds[0] = ptr;

            IntPtr[] values = new IntPtr[1];
            values[0] = (IntPtr)value;

            IntPtr[] mvalues = null;

            if (mValue != 0)
            {
                mvalues = new IntPtr[1];
                mvalues[0] = (IntPtr)mValue;
            }

            var gens = Generators();
            var scratch = secp256k1_scratch_space_create.Value(Context, Constant.SCRATCH_SPACE_SIZE);
            var result = secp256k1_bulletproof_rangeproof_prove.Value(
                            Context,
                            scratch,
                            gens,
                            proof,
                            ref plen,
                            tau_x,
                            t_one,
                            t_two,
                            values,
                            mvalues,
                            blinds,
                            commits,
                            1,
                            Constant.GENERATOR_H,
                            64,
                            nonce,
                            rewindNonce,
                            extraCommit,
                            extraCommitLen,
                            msg);

            if (result == 1)
            {
                Array.Resize(ref proof, plen);
            }

            _ = secp256k1_scratch_space_destroy.Value(scratch);

            return new ProofStruct(proof, (uint)plen);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="commit"></param>
        /// <param name="nonce"></param>
        /// <param name="extraData"></param>
        /// <param name="proof"></param>
        /// <returns></returns>
        public ProofInfoStruct RewindBulletProof(byte[] commit, byte[] nonce, byte[] extraData, ProofStruct proof)
        {
            var blindOut = new byte[Constant.SECRET_KEY_SIZE];
            var valueOut = 0ul;
            var messageOut = new byte[20];
            
            using var pedersen = new Pedersen();
            commit = pedersen.CommitParse(commit);
            
            var scratch = secp256k1_scratch_space_create.Value(Context, Constant.SCRATCH_SPACE_SIZE);
            var result = secp256k1_bulletproof_rangeproof_rewind.Value(
                            Context,
                            ref valueOut,
                            blindOut,
                            proof.proof,
                            proof.plen,
                            0,
                            commit,
                            Constant.GENERATOR_H,
                            nonce,
                            extraData,
                            extraData == null ? 0 : extraData.Length,
                            messageOut);
            
            _ = secp256k1_scratch_space_destroy.Value(scratch);

            return result != 1
                ? default
                : new ProofInfoStruct(true, valueOut, messageOut, blindOut, 0, 0, ulong.MaxValue, 0, 0);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="commit"></param>
        /// <param name="proof"></param>
        /// <param name="extraCommit"></param>
        /// <param name="mValue"></param>
        /// <returns></returns>
        public bool Verify(byte[] commit, byte[] proof, byte[] extraCommit, int mValue = 0)
        {
            var extraCommitLen = extraCommit == null ? 0 : extraCommit.Length;
            var gens = Generators();
            var scratch = secp256k1_scratch_space_create.Value(Context, Constant.SCRATCH_SPACE_SIZE);

            IntPtr[] mvalues = null;

            if (mValue != 0)
            {
                mvalues = new IntPtr[1];
                mvalues[0] = (IntPtr)mValue;
            }

            bool success = secp256k1_bulletproof_rangeproof_verify.Value(
                            Context,
                            scratch,
                            gens,
                            proof,
                            proof.Length,
                            mvalues,
                            commit,
                            1,
                            64,
                            Constant.GENERATOR_H,
                            extraCommit,
                            extraCommitLen) == 1;

            _ = secp256k1_scratch_space_destroy.Value(scratch);

            return success;
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
