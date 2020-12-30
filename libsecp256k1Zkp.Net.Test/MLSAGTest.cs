using System;
using System.Collections.Generic;
using System.Linq;

using FluentAssertions;

using Xunit;

namespace Libsecp256k1Zkp.Net.Test
{
    public unsafe class MLSAGTest
    {
        [Fact]
        public void RingCT_Test()
        {
            const int COIN = 1000_000;

            var secp256k1 = new Secp256k1();
            var pedersen = new Pedersen();
            var mlsag = new MLSAG();

            var blinds = new Span<byte[]>(new byte[3][]);
            var sk = new Span<byte[]>(new byte[2][]);
            int nRows = 1 + 1; // last row sums commitments
            int nCols = 1 + (Util.Rand() % 32); // ring size
            int index = Util.Rand() % nCols;
            var m = new byte[nRows * nCols * 33];
            var pcm_in = new Span<byte[]>(new byte[nCols * 1][]);
            var pcm_out = new Span<byte[]>(new byte[2][]);
            var randSeed = secp256k1.Randomize32();
            var preimage = secp256k1.Randomize32();
            var pc = new byte[32];
            var ki = new byte[33 * 1];
            var ss = new byte[nCols * nRows * 32];

            List<ulong> amount_outs = new List<ulong>
            {
                (ulong)5.69 * COIN,
                (ulong)40 * COIN
            };

            foreach ((ulong amount, int i) a in amount_outs.Select((x, i) => (x, i)))
            {
                blinds[a.i + 1] = secp256k1.Randomize32();
                pcm_out[a.i] = pedersen.Commit(a.amount, blinds[a.i + 1]);
            }

            for (int k = 0; k < nRows - 1; ++k)
                for (int i = 0; i < nCols; ++i)
                {
                    if (i == index)
                    {
                        var kp = secp256k1.GenerateKeyPair(true);

                        sk[0] = kp.PrivateKey;
                        blinds[0] = secp256k1.Randomize32();
                        pcm_in[i + k * nCols] = pedersen.Commit((ulong)45.69 * COIN, blinds[0]);

                        fixed (byte* mm = m, pk = kp.PublicKey)
                        {
                            Util.MemCpy(&mm[(i + k * nCols) * 33], pk, 33);
                        }
                        continue;
                    }

                    // Make fake input
                    var fakeAmountIn = Util.Rand() % (500 * COIN);
                    pcm_in[i + k * nCols] = pedersen.Commit((ulong)fakeAmountIn, secp256k1.Randomize32());

                    fixed (byte* mm = m, pk = secp256k1.CreatePublicKey(secp256k1.Randomize32(), true))
                    {
                        Util.MemCpy(&mm[(i + k * nCols) * 33], pk, 33);
                    }
                }

            var blindSum = new byte[32];
            var pv = mlsag.Prepare(m, blindSum, amount_outs.Count, amount_outs.Count, nCols, nRows, pcm_in, pcm_out, blinds);

            pv.Should().Be(true);

            sk[nRows - 1] = blindSum;

            var gv = mlsag.Generate(ki, pc, ss, randSeed, preimage, nCols, nRows, index, sk, m);

            gv.Should().Be(true);

            var vv = mlsag.Verify(preimage, nCols, nRows, m, ki, pc, ss);

            vv.Should().Be(true);

            /* Bad preimage */
            var vv1 = mlsag.Verify(randSeed, nCols, nRows, m, ki, pc, ss);

            vv1.Should().Be(false);

            /* Bad c */
            var vv2 = mlsag.Verify(preimage, nCols, nRows, m, ki, randSeed, ss);

            vv2.Should().Be(false);

            secp256k1.Dispose();
            pedersen.Dispose();
        }

    }
}
