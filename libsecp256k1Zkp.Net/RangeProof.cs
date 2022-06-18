using System;
using Libsecp256k1Zkp.Net.Linking;
using static Libsecp256k1Zkp.Net.RangeProofNative;

namespace Libsecp256k1Zkp.Net
{
    public class RangeProof : IDisposable
    {
        private readonly Lazy<secp256k1_context_create> secp256k1_context_create;
        private readonly Lazy<secp256k1_rangeproof_sign> secp256k1_rangeproof_sign;
        private readonly Lazy<secp256k1_rangeproof_info> secp256k1_rangeproof_info;
        private readonly Lazy<secp256k1_rangeproof_rewind> secp256k1_rangeproof_rewind;
        private readonly Lazy<secp256k1_rangeproof_verify> secp256k1_rangeproof_verify;
        private readonly Lazy<secp256k1_context_destroy> secp256k1_context_destroy;
        
        private static readonly Lazy<string> _libPath = new(() => Resolver.Resolve(Constant.LIB));
        private static readonly Lazy<IntPtr> _libPtr = new(() => LoadNative.LoadLib(_libPath.Value));
        
        public IntPtr Context { get; private set; }

        public RangeProof()
        {
            secp256k1_context_create = Util.LazyDelegate<secp256k1_context_create>(_libPtr);
            secp256k1_rangeproof_sign = Util.LazyDelegate<secp256k1_rangeproof_sign>(_libPtr);
            secp256k1_rangeproof_info = Util.LazyDelegate<secp256k1_rangeproof_info>(_libPtr);
            secp256k1_rangeproof_rewind = Util.LazyDelegate<secp256k1_rangeproof_rewind>(_libPtr);
            secp256k1_rangeproof_verify = Util.LazyDelegate<secp256k1_rangeproof_verify>(_libPtr);
            secp256k1_context_destroy = Util.LazyDelegate<secp256k1_context_destroy>(_libPtr);

            Context = secp256k1_context_create.Value((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
        }

        /// <summary>
        /// Produces a range proof for the provided value, using min and max.
        /// </summary>
        /// <returns>The proof.</returns>
        /// <param name="min">Minimum.</param>
        /// <param name="value">Value.</param>
        /// <param name="blind">Blind.</param>
        /// <param name="commit">Commit.</param>
        /// <param name="msg">Message.</param>
        public ProofStruct Proof(ulong min, ulong value, byte[] blind, byte[] commit, byte[] msg)
        {
            if (blind.Length < Constant.BLIND_LENGTH)
                throw new ArgumentException($"{nameof(blind)} must be {Constant.BLIND_LENGTH} bytes");

            if (commit.Length < Constant.PEDERSEN_COMMITMENT_SIZE)
                throw new ArgumentException($"{nameof(commit)} must be {Constant.PEDERSEN_COMMITMENT_SIZE} bytes");

            bool success = false;
            byte[] proof = new byte[Constant.MAX_PROOF_SIZE];
            uint plen = Constant.MAX_PROOF_SIZE;
            byte[] nonce = (byte[])blind.Clone();
            byte[] extraCommit = new byte[33];

            using var pedersen = new Pedersen();

            commit = pedersen.CommitParse(commit);

            while (success == false)
            {
                success = secp256k1_rangeproof_sign.Value(
                            Context,
                            proof,
                            ref plen,
                            min,
                            commit,
                            blind,
                            nonce,
                            0,
                            64,
                            value,
                            msg,
                            (uint)msg.Length,
                            extraCommit,
                            0,
                            Constant.GENERATOR_H) == 1;
            }

            return new ProofStruct(proof, plen);
        }

        /// <summary>
        /// General information extracted from a range proof.
        /// </summary>
        /// <returns>The info.</returns>
        /// <param name="struct">Proof.</param>
        public ProofInfoStruct Info(ProofStruct @struct)
        {
            int exp = 0, mantissa = 0;
            ulong min = 0, max = 0;

            using var secp256k1 = new Secp256k1();

            var secretKey = secp256k1.CreatePrivateKey();

            var success = secp256k1_rangeproof_info.Value(
                            Context,
                            ref exp,
                            ref mantissa,
                            ref min,
                            ref max,
                            @struct.proof,
                            @struct.plen) == 1;

            return new ProofInfoStruct(
                        success,
                        0,
                        new byte[Constant.PROOF_MSG_SIZE],
                        secretKey,
                        0,
                        min,
                        max,
                        exp,
                        mantissa);
        }

        /// <summary>
        /// Verify a range proof and rewind the proof to recover information
        /// sent by its author.
        /// </summary>
        /// <returns>The rewind.</returns>
        /// <param name="commit">Commit.</param>
        /// <param name="struct">Proof.</param>
        /// <param name="nonce">Nonce.</param>
        public ProofInfoStruct Rewind(byte[] commit, ProofStruct @struct, byte[] nonce)
        {
            if (commit.Length < Constant.PEDERSEN_COMMITMENT_SIZE)
                throw new ArgumentException($"{nameof(commit)} must be {Constant.PEDERSEN_COMMITMENT_SIZE} bytes");

            if (nonce.Length < Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(nonce)} must be {Constant.SECRET_KEY_SIZE} bytes");

            ulong value = 0, min = 0, max = 0;
            byte[] blindOut = new byte[32];
            byte[] message = new byte[Constant.PROOF_MSG_SIZE];
            uint mlen = Constant.PROOF_MSG_SIZE;
            byte[] extraCommit = new byte[33];

            using var pedersen = new Pedersen();

            commit = pedersen.CommitParse(commit);

            var success = secp256k1_rangeproof_rewind.Value(
                            Context,
                            blindOut,
                            ref value,
                            message,
                            ref mlen,
                            nonce,
                            ref min,
                            ref max,
                            commit,
                            @struct.proof,
                            @struct.plen,
                            extraCommit,
                            0,
                            Constant.GENERATOR_H
                            ) == 1;

            return new ProofInfoStruct(
                        success,
                        value,
                        message,
                        blindOut,
                        mlen,
                        min,
                        max,
                        0,
                        0);
        }

        /// <summary>
        /// Verify a proof that a committed value is within a range.
        /// </summary>
        /// <returns>The verify.</returns>
        /// <param name="commit">Commit.</param>
        /// <param name="struct">Proof.</param>
        public bool Verify(byte[] commit, ProofStruct @struct)
        {
            if (commit.Length < Constant.PEDERSEN_COMMITMENT_SIZE)
                throw new ArgumentException($"{nameof(commit)} must be {Constant.PEDERSEN_COMMITMENT_SIZE} bytes");

            bool success;
            ulong min = 0, max = 0;
            byte[] extraCommit = new byte[33];

            using (var pedersen = new Pedersen())
            {
                commit = pedersen.CommitParse(commit);

                success = secp256k1_rangeproof_verify.Value(
                    Context,
                    ref min,
                    ref max,
                    commit,
                    @struct.proof,
                    @struct.plen,
                    extraCommit,
                    0,
                    Constant.GENERATOR_H) == 1;
            }

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
