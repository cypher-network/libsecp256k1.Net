using System;
using System.Collections.Generic;
using System.Text;

using Libsecp256k1Zkp.Net;

namespace Example
{
    unsafe class Program
    {
        static void Main(string[] args)
        {
            using var secp256K1 = new Secp256k1();
            using var pedersen = new Pedersen();
            using var bulletProof = new BulletProof();
            using var rangeProof = new RangeProof();

            const ulong value = 1000;
            var blinding = secp256K1.CreatePrivateKey();
            var commit = pedersen.Commit(value, blinding);
            var @struct = bulletProof.GenerateBulletProof(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null!, null!);
            var success = bulletProof.Verify(commit, @struct.proof, null!);
            var rewind = bulletProof.RewindBulletProof(commit, (byte[])blinding.Clone(), null!, @struct);
            
            byte[]? Commit(ulong mValue)
            {
                var zeroKey = new byte[32];
                return pedersen.Commit(mValue, zeroKey);
            }

            var a = pedersen.VerifyCommitSum(new List<byte[]> { }, new List<byte[]> { });
            var b = pedersen.VerifyCommitSum(new List<byte[]> { Commit(5) }, new List<byte[]> { Commit(5) });
            var c = pedersen.VerifyCommitSum(new List<byte[]> { Commit(3), Commit(2) }, new List<byte[]> { Commit(5) });
            var d = pedersen.VerifyCommitSum(new List<byte[]> { Commit(2), Commit(4) },
                new List<byte[]> { Commit(1), Commit(5) });
        }

        static void SignWithPubKeyFromCommitment()
        {
            using var secp256K1 = new Secp256k1();
            using var pedersen = new Pedersen();

            static string ToHex(byte[] data)
            {
                return BitConverter.ToString(data).Replace("-", string.Empty);
            }

            var blinding = secp256K1.CreatePrivateKey();
            var commit = pedersen.Commit(0, blinding);

            var msg = "Message for signing";
            var msgBytes = Encoding.UTF8.GetBytes(msg);
            var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

            var sig = secp256K1.Sign(msgHash, blinding);

            var pubKey = pedersen.ToPublicKey(commit);

            var t = secp256K1.Verify(sig, msgHash, pubKey);

            var actualPubKey = secp256K1.CreatePublicKey(blinding);

            var eq = ToHex(pubKey) == ToHex(actualPubKey);
        }


        static void VerifyBatchSigning()
        {
            using var secp256k1 = new Secp256k1();
            using var schnorrSig = new Schnorr();

            var signatures = new List<byte[]>();
            var messages = new List<byte[]>();
            var publicKeys = new List<byte[]>();

            for (int i = 0; i < 10; i++)
            {
                var keyPair = secp256k1.GenerateKeyPair();

                var msg = $"Message for signing {i}";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var sig = schnorrSig.Sign(msgHash, keyPair.PrivateKey);

                signatures.Add(sig);
                publicKeys.Add(keyPair.PublicKey);

                msg = $"Message for signing wrong {i}";
                msgBytes = Encoding.UTF8.GetBytes(msg);
                msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                messages.Add(msgHash);
            }

            var valid = schnorrSig.VerifyBatch(signatures, messages, publicKeys);
        }
    }
}
