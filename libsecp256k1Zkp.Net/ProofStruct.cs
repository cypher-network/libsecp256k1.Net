namespace Libsecp256k1Zkp.Net
{
    public struct ProofStruct
    {
        public byte[] proof;
        public uint plen;

        public ProofStruct(byte[] proof, uint plen)
        {
            this.proof = proof;
            this.plen = plen;
        }
    }
}