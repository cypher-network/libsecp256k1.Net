using Xunit;

namespace Libsecp256k1Zkp.Net.Test
{
    public class BulletproofTest
    {
        [Fact]
        public void Bullet_Proof()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var bulletProof = new BulletProof())
            {
                // Correct value
                ulong value = 300;
                var blinding = secp256k1.CreatePrivateKey();
                var commit = pedersen.Commit(value, blinding);
                var @struct = bulletProof.GenerateBulletProof(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
                var success = bulletProof.Verify(commit, @struct.proof, null);

                Assert.True(success);

                // Wrong value
                value = 1222344;
                var commitWrong = pedersen.Commit(122111, blinding);
                @struct = bulletProof.GenerateBulletProof(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
                success = bulletProof.Verify(commit, @struct.proof, null);

                Assert.False(success);

                // Wrong binding
                value = 122322;
                commit = pedersen.Commit(value, blinding);
                blinding = secp256k1.CreatePrivateKey();
                @struct = bulletProof.GenerateBulletProof(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
                success = bulletProof.Verify(commit, @struct.proof, null);

                Assert.False(success);
            }
        }

        [Fact]
        public void Bullet_Proof_Minimum_Amount()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var bulletProof = new BulletProof())
            {
                int minValue = 1000;
                ulong value = 300;

                // Correct value and minimum value
                var blinding = secp256k1.CreatePrivateKey();
                var commit = pedersen.Commit(value, blinding);
                var @struct = bulletProof.GenerateBulletProof(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
                var success = bulletProof.Verify(commit, @struct.proof, null);

                Assert.True(success);

                // Wrong value < 1000 and minimum value.
                var commitWrong = pedersen.Commit(value, blinding);
                @struct = bulletProof.GenerateBulletProof(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null, minValue);
                success = bulletProof.Verify(commit, @struct.proof, null, minValue);

                Assert.False(success);
            }
        }

        [Fact]
        public void Bullet_Proof_Extra_Commit()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var bulletProof = new BulletProof())
            {
                var extraCommit = new byte[32];
                var blinding = secp256k1.CreatePrivateKey();
                ulong value = 100033;
                var commit = pedersen.Commit(value, blinding);
                var @struct = bulletProof.GenerateBulletProof(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), extraCommit, null);
                var success = bulletProof.Verify(commit, @struct.proof, extraCommit);

                Assert.True(success);
            }
        }

        [Fact]
        public void Bullet_Proof_Extra_Commit_Wrong()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var bulletProof = new BulletProof())
            {
                // Correct extra commit
                var extraCommit = new byte[32];
                var blinding = secp256k1.CreatePrivateKey();
                ulong value = 100033;
                var commit = pedersen.Commit(value, blinding);
                var @struct = bulletProof.GenerateBulletProof(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), extraCommit, null);
                var success = bulletProof.Verify(commit, @struct.proof, extraCommit);

                Assert.True(success);


                //Wrong extra commit
                var extraCommitWrong = new byte[32];
                extraCommitWrong[0] = 1;
                success = bulletProof.Verify(commit, @struct.proof, extraCommitWrong);

                Assert.False(success);
            }
        }
    }
}
