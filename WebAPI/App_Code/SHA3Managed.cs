#region

using System;

#endregion

namespace LinkologyPUSHTimeclock
{
    public class SHA3Managed : SHA3
    {
        public SHA3Managed(int hashBitLength)
            : base(hashBitLength)
        {
        }

        protected
            override
            void HashCore(byte[] array, int ibStart, int cbSize)
        {
            base.HashCore(array, ibStart, cbSize);
            if (cbSize == 0)
                return;
            var sizeInBytes = SizeInBytes;
            if (Buffer == null)
                Buffer = new byte[sizeInBytes];
            var stride = sizeInBytes >> 3;
            var utemps = new ulong[stride];
            if (BuffLength == sizeInBytes)
                throw new Exception("Unexpected error, the internal buffer is full");
            AddToBuffer(array, ref ibStart, ref cbSize);
            if (BuffLength == sizeInBytes) //buffer full
            {
                System.Buffer.BlockCopy(Buffer, 0, utemps, 0, sizeInBytes);
                KeccakF(utemps, stride);
                BuffLength = 0;
            }
            for (; cbSize >= sizeInBytes; cbSize -= sizeInBytes, ibStart += sizeInBytes)
            {
                System.Buffer.BlockCopy(array, ibStart, utemps, 0, sizeInBytes);
                KeccakF(utemps, stride);
            }
            if (cbSize > 0) //some left over
            {
                System.Buffer.BlockCopy(array, ibStart, Buffer, BuffLength, cbSize);
                BuffLength += cbSize;
            }
        }

        protected
            override
            byte[] HashFinal()
        {
            var sizeInBytes = SizeInBytes;
            var outb = new byte[HashByteLength];
            //    padding
            if (Buffer == null)
                Buffer = new byte[sizeInBytes];
            else
                Array.Clear(Buffer, BuffLength, sizeInBytes - BuffLength);
            Buffer[BuffLength++] = 1;
            Buffer[sizeInBytes - 1] |= 0x80;
            var stride = sizeInBytes >> 3;
            var utemps = new ulong[stride];
            System.Buffer.BlockCopy(Buffer, 0, utemps, 0, sizeInBytes);
            KeccakF(utemps, stride);
            System.Buffer.BlockCopy(Sha3State, 0, outb, 0, HashByteLength);
            return outb;
        }

        private void KeccakF(ulong[] inb, int laneCount)
        {
            while (--laneCount >= 0)
                Sha3State[laneCount] ^= inb[laneCount];
            ulong Aba, Abe, Abi, Abo, Abu;
            ulong Aga, Age, Agi, Ago, Agu;
            ulong Aka, Ake, Aki, Ako, Aku;
            ulong Ama, Ame, Ami, Amo, Amu;
            ulong Asa, Ase, Asi, Aso, Asu;
            ulong BCa, BCe, BCi, BCo, BCu;
            ulong Da, De, Di, Do, Du;
            ulong Eba, Ebe, Ebi, Ebo, Ebu;
            ulong Ega, Ege, Egi, Ego, Egu;
            ulong Eka, Eke, Eki, Eko, Eku;
            ulong Ema, Eme, Emi, Emo, Emu;
            ulong Esa, Ese, Esi, Eso, Esu;

            //copyFromSha3State(A, Sha3State)
            Aba = Sha3State[0];
            Abe = Sha3State[1];
            Abi = Sha3State[2];
            Abo = Sha3State[3];
            Abu = Sha3State[4];
            Aga = Sha3State[5];
            Age = Sha3State[6];
            Agi = Sha3State[7];
            Ago = Sha3State[8];
            Agu = Sha3State[9];
            Aka = Sha3State[10];
            Ake = Sha3State[11];
            Aki = Sha3State[12];
            Ako = Sha3State[13];
            Aku = Sha3State[14];
            Ama = Sha3State[15];
            Ame = Sha3State[16];
            Ami = Sha3State[17];
            Amo = Sha3State[18];
            Amu = Sha3State[19];
            Asa = Sha3State[20];
            Ase = Sha3State[21];
            Asi = Sha3State[22];
            Aso = Sha3State[23];
            Asu = Sha3State[24];

            for (var round = 0; round < KeccakNumberOfRounds; round += 2)
            {
                //    prepareTheta
                BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
                BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
                BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
                BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
                BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

                //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
                Da = BCu ^ ROL(BCe, 1);
                De = BCa ^ ROL(BCi, 1);
                Di = BCe ^ ROL(BCo, 1);
                Do = BCi ^ ROL(BCu, 1);
                Du = BCo ^ ROL(BCa, 1);

                Aba ^= Da;
                BCa = Aba;
                Age ^= De;
                BCe = ROL(Age, 44);
                Aki ^= Di;
                BCi = ROL(Aki, 43);
                Amo ^= Do;
                BCo = ROL(Amo, 21);
                Asu ^= Du;
                BCu = ROL(Asu, 14);
                Eba = BCa ^ ((~BCe) & BCi);
                Eba ^= RoundConstants[round];
                Ebe = BCe ^ ((~BCi) & BCo);
                Ebi = BCi ^ ((~BCo) & BCu);
                Ebo = BCo ^ ((~BCu) & BCa);
                Ebu = BCu ^ ((~BCa) & BCe);

                Abo ^= Do;
                BCa = ROL(Abo, 28);
                Agu ^= Du;
                BCe = ROL(Agu, 20);
                Aka ^= Da;
                BCi = ROL(Aka, 3);
                Ame ^= De;
                BCo = ROL(Ame, 45);
                Asi ^= Di;
                BCu = ROL(Asi, 61);
                Ega = BCa ^ ((~BCe) & BCi);
                Ege = BCe ^ ((~BCi) & BCo);
                Egi = BCi ^ ((~BCo) & BCu);
                Ego = BCo ^ ((~BCu) & BCa);
                Egu = BCu ^ ((~BCa) & BCe);

                Abe ^= De;
                BCa = ROL(Abe, 1);
                Agi ^= Di;
                BCe = ROL(Agi, 6);
                Ako ^= Do;
                BCi = ROL(Ako, 25);
                Amu ^= Du;
                BCo = ROL(Amu, 8);
                Asa ^= Da;
                BCu = ROL(Asa, 18);
                Eka = BCa ^ ((~BCe) & BCi);
                Eke = BCe ^ ((~BCi) & BCo);
                Eki = BCi ^ ((~BCo) & BCu);
                Eko = BCo ^ ((~BCu) & BCa);
                Eku = BCu ^ ((~BCa) & BCe);

                Abu ^= Du;
                BCa = ROL(Abu, 27);
                Aga ^= Da;
                BCe = ROL(Aga, 36);
                Ake ^= De;
                BCi = ROL(Ake, 10);
                Ami ^= Di;
                BCo = ROL(Ami, 15);
                Aso ^= Do;
                BCu = ROL(Aso, 56);
                Ema = BCa ^ ((~BCe) & BCi);
                Eme = BCe ^ ((~BCi) & BCo);
                Emi = BCi ^ ((~BCo) & BCu);
                Emo = BCo ^ ((~BCu) & BCa);
                Emu = BCu ^ ((~BCa) & BCe);

                Abi ^= Di;
                BCa = ROL(Abi, 62);
                Ago ^= Do;
                BCe = ROL(Ago, 55);
                Aku ^= Du;
                BCi = ROL(Aku, 39);
                Ama ^= Da;
                BCo = ROL(Ama, 41);
                Ase ^= De;
                BCu = ROL(Ase, 2);
                Esa = BCa ^ ((~BCe) & BCi);
                Ese = BCe ^ ((~BCi) & BCo);
                Esi = BCi ^ ((~BCo) & BCu);
                Eso = BCo ^ ((~BCu) & BCa);
                Esu = BCu ^ ((~BCa) & BCe);

                //    prepareTheta
                BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
                BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
                BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
                BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
                BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

                //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
                Da = BCu ^ ROL(BCe, 1);
                De = BCa ^ ROL(BCi, 1);
                Di = BCe ^ ROL(BCo, 1);
                Do = BCi ^ ROL(BCu, 1);
                Du = BCo ^ ROL(BCa, 1);

                Eba ^= Da;
                BCa = Eba;
                Ege ^= De;
                BCe = ROL(Ege, 44);
                Eki ^= Di;
                BCi = ROL(Eki, 43);
                Emo ^= Do;
                BCo = ROL(Emo, 21);
                Esu ^= Du;
                BCu = ROL(Esu, 14);
                Aba = BCa ^ ((~BCe) & BCi);
                Aba ^= RoundConstants[round + 1];
                Abe = BCe ^ ((~BCi) & BCo);
                Abi = BCi ^ ((~BCo) & BCu);
                Abo = BCo ^ ((~BCu) & BCa);
                Abu = BCu ^ ((~BCa) & BCe);

                Ebo ^= Do;
                BCa = ROL(Ebo, 28);
                Egu ^= Du;
                BCe = ROL(Egu, 20);
                Eka ^= Da;
                BCi = ROL(Eka, 3);
                Eme ^= De;
                BCo = ROL(Eme, 45);
                Esi ^= Di;
                BCu = ROL(Esi, 61);
                Aga = BCa ^ ((~BCe) & BCi);
                Age = BCe ^ ((~BCi) & BCo);
                Agi = BCi ^ ((~BCo) & BCu);
                Ago = BCo ^ ((~BCu) & BCa);
                Agu = BCu ^ ((~BCa) & BCe);

                Ebe ^= De;
                BCa = ROL(Ebe, 1);
                Egi ^= Di;
                BCe = ROL(Egi, 6);
                Eko ^= Do;
                BCi = ROL(Eko, 25);
                Emu ^= Du;
                BCo = ROL(Emu, 8);
                Esa ^= Da;
                BCu = ROL(Esa, 18);
                Aka = BCa ^ ((~BCe) & BCi);
                Ake = BCe ^ ((~BCi) & BCo);
                Aki = BCi ^ ((~BCo) & BCu);
                Ako = BCo ^ ((~BCu) & BCa);
                Aku = BCu ^ ((~BCa) & BCe);

                Ebu ^= Du;
                BCa = ROL(Ebu, 27);
                Ega ^= Da;
                BCe = ROL(Ega, 36);
                Eke ^= De;
                BCi = ROL(Eke, 10);
                Emi ^= Di;
                BCo = ROL(Emi, 15);
                Eso ^= Do;
                BCu = ROL(Eso, 56);
                Ama = BCa ^ ((~BCe) & BCi);
                Ame = BCe ^ ((~BCi) & BCo);
                Ami = BCi ^ ((~BCo) & BCu);
                Amo = BCo ^ ((~BCu) & BCa);
                Amu = BCu ^ ((~BCa) & BCe);

                Ebi ^= Di;
                BCa = ROL(Ebi, 62);
                Ego ^= Do;
                BCe = ROL(Ego, 55);
                Eku ^= Du;
                BCi = ROL(Eku, 39);
                Ema ^= Da;
                BCo = ROL(Ema, 41);
                Ese ^= De;
                BCu = ROL(Ese, 2);
                Asa = BCa ^ ((~BCe) & BCi);
                Ase = BCe ^ ((~BCi) & BCo);
                Asi = BCi ^ ((~BCo) & BCu);
                Aso = BCo ^ ((~BCu) & BCa);
                Asu = BCu ^ ((~BCa) & BCe);
            }

            //copyToSha3State(Sha3State, A)
            Sha3State[0] = Aba;
            Sha3State[1] = Abe;
            Sha3State[2] = Abi;
            Sha3State[3] = Abo;
            Sha3State[4] = Abu;
            Sha3State[5] = Aga;
            Sha3State[6] = Age;
            Sha3State[7] = Agi;
            Sha3State[8] = Ago;
            Sha3State[9] = Agu;
            Sha3State[10] = Aka;
            Sha3State[11] = Ake;
            Sha3State[12] = Aki;
            Sha3State[13] = Ako;
            Sha3State[14] = Aku;
            Sha3State[15] = Ama;
            Sha3State[16] = Ame;
            Sha3State[17] = Ami;
            Sha3State[18] = Amo;
            Sha3State[19] = Amu;
            Sha3State[20] = Asa;
            Sha3State[21] = Ase;
            Sha3State[22] = Asi;
            Sha3State[23] = Aso;
            Sha3State[24] = Asu;
        }
    }
}