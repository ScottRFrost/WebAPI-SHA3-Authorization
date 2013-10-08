#region

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

#endregion

namespace LinkologyPUSHTimeclock
{
    /// <summary>
    /// Adapted from https://bitbucket.org/mmsaffari/sha3
    /// </summary>
    public abstract class SHA3 : HashAlgorithm
    {
        #region Statics

        private const string DefaultHashName = "SHA512";

        private static readonly Dictionary<string, Func<SHA3>> HashNameMap;

        static SHA3()
        {
            HashNameMap = new Dictionary<string, Func<SHA3>>();
        }

        public new static SHA3 Create(string hashName = DefaultHashName)
        {
            Func<SHA3> ctor;
            return HashNameMap.TryGetValue(hashName, out ctor) ? ctor() : null;
        }

        #endregion

        #region Implementation

        protected const int KeccakB = 1600;
        protected const int KeccakNumberOfRounds = 24;
        protected const int KeccakLaneSizeInBits = 8 * 8;

        protected readonly ulong[] RoundConstants;

        protected int BuffLength;
        protected byte[] Buffer;
        protected ulong[] Sha3State;

        public
            override
            bool CanReuseTransform
        {
            get { return true; }
        }

        public
            override
            byte[] Hash
        {
            get { return HashValue; }
        }

        protected int HashByteLength
        {
            get { return HashSizeValue/8; }
        }

        public
            override
            int HashSize
        {
            get { return HashSizeValue; }
        }

        private int KeccakR { get; set; }

        protected int SizeInBytes
        {
            get { return KeccakR/8; }
        }

        protected SHA3(int hashBitLength)
        {
            if (hashBitLength != 224 && hashBitLength != 256 && hashBitLength != 384 && hashBitLength != 512)
                throw new ArgumentException("hashBitLength must be 224, 256, 384, or 512", "hashBitLength");
            Initialize();
            HashSizeValue = hashBitLength;
            switch (hashBitLength)
            {
                case 224:
                    KeccakR = 1152;
                    break;
                case 256:
                    KeccakR = 1088;
                    break;
                case 384:
                    KeccakR = 832;
                    break;
                case 512:
                    KeccakR = 576;
                    break;
            }
            RoundConstants = new[]
            {
                0x0000000000000001UL,
                0x0000000000008082UL,
                0x800000000000808aUL,
                0x8000000080008000UL,
                0x000000000000808bUL,
                0x0000000080000001UL,
                0x8000000080008081UL,
                0x8000000000008009UL,
                0x000000000000008aUL,
                0x0000000000000088UL,
                0x0000000080008009UL,
                0x000000008000000aUL,
                0x000000008000808bUL,
                0x800000000000008bUL,
                0x8000000000008089UL,
                0x8000000000008003UL,
                0x8000000000008002UL,
                0x8000000000000080UL,
                0x000000000000800aUL,
                0x800000008000000aUL,
                0x8000000080008081UL,
                0x8000000000008080UL,
                0x0000000080000001UL,
                0x8000000080008008UL
            };
        }

        protected ulong ROL(ulong a, int offset)
        {
            return (((a) << ((offset)%KeccakLaneSizeInBits)) ^
                    ((a) >> (KeccakLaneSizeInBits - ((offset)%KeccakLaneSizeInBits))));
        }

        protected void AddToBuffer(byte[] array, ref int offset, ref int count)
        {
            var amount = Math.Min(count, Buffer.Length - BuffLength);
            System.Buffer.BlockCopy(array, offset, Buffer, BuffLength, amount);
            offset += amount;
            BuffLength += amount;
            count -= amount;
        }

        #endregion

        public
            override sealed void Initialize()
        {
            BuffLength = 0;
            Sha3State = new ulong[5 * 5]; //1600 bits
            HashValue = null;
        }

        protected
            override
            void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (array == null)
                throw new ArgumentNullException("array");
            if (ibStart < 0)
                throw new ArgumentOutOfRangeException("ibStart");
            if (cbSize > array.Length)
                throw new ArgumentOutOfRangeException("cbSize");
            if (ibStart + cbSize > array.Length)
                throw new ArgumentOutOfRangeException("ibStart");
        }
    }
}