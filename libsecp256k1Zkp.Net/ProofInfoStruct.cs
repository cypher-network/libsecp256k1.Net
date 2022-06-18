namespace Libsecp256k1Zkp.Net
{
    public struct ProofInfoStruct
    {
        public bool success;
        public ulong value;
        public byte[] message;
        public byte[] blindin;
        public uint mlen;
        public ulong min;
        public ulong max;
        public int exp;
        public int mantissa;

        public ProofInfoStruct(bool success, ulong value, byte[] message, byte[] blindin, uint mlen, ulong min, ulong max, int exp, int mantissa)
        {
            this.success = success;
            this.value = value;
            this.message = message;
            this.blindin = blindin;
            this.mlen = mlen;
            this.min = min;
            this.max = max;
            this.exp = exp;
            this.mantissa = mantissa;
        }
    }
}