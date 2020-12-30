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
            using var secp256k1 = new Secp256k1();
            using var pedersen = new Pedersen();
            using var bulletProof = new BulletProof();

            ulong value = 1000;
            var blinding = secp256k1.CreatePrivateKey();
            var commit = pedersen.Commit(value, blinding);
            var @struct = bulletProof.GenProof(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
            var success = bulletProof.Verify(commit, @struct.proof, null);
        }

        static void SignWithPubKeyFromCommitment()
        {
            using var secp256k1 = new Secp256k1();
            using var pedersen = new Pedersen();

            static string ToHex(byte[] data)
            {
                return BitConverter.ToString(data).Replace("-", string.Empty);
            }

            var blinding = secp256k1.CreatePrivateKey();
            var commit = pedersen.Commit(0, blinding);

            var msg = "Message for signing";
            var msgBytes = Encoding.UTF8.GetBytes(msg);
            var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

            var sig = secp256k1.Sign(msgHash, blinding);

            var pubKey = pedersen.ToPublicKey(commit);

            var t = secp256k1.Verify(sig, msgHash, pubKey);

            var actualPubKey = secp256k1.CreatePublicKey(blinding);

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
