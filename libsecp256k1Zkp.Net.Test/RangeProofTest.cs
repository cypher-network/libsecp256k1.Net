using System.Text;

using Xunit;

namespace Libsecp256k1Zkp.Net.Test
{
    public class RangeProofTest
    {
        [Fact]
        public void Range_Proof()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var rangeProof = new RangeProof())
            {
                var blinding = secp256k1.CreatePrivateKey();
                var commit = pedersen.Commit(9, blinding);
                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);
                var proof = rangeProof.Proof(0, 9, blinding, commit, msgHash);
                var verified = rangeProof.Verify(commit, proof);
                Assert.True(verified);

                var proofInfo = rangeProof.Info(proof);
                Assert.True(proofInfo.success);
                Assert.Equal(0, (long)proofInfo.min);
                Assert.Equal(0, (long)proofInfo.value);

                proofInfo = rangeProof.Rewind(commit, proof, blinding);
                Assert.True(proofInfo.success);
                Assert.Equal(0, (long)proofInfo.min);
                Assert.Equal(9, (long)proofInfo.value);

                var badNonce = secp256k1.CreatePrivateKey();
                var badInfo = rangeProof.Rewind(commit, proof, badNonce);
                Assert.False(badInfo.success);
                Assert.Equal(0, (long)badInfo.value);

                commit = pedersen.Commit(0, blinding);
                proof = rangeProof.Proof(0, 0, blinding, commit, msgHash);
                rangeProof.Verify(commit, proof);
                proofInfo = rangeProof.Rewind(commit, proof, blinding);
                Assert.True(proofInfo.success);
                Assert.Equal(0, (long)proofInfo.min);
                Assert.Equal(0, (long)proofInfo.value);
            }
        }
    }
}
