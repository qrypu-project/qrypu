using System;

namespace qrypu.Core.Test.NetCore.Common
{
    public static class TestUtils
    {
        public static byte[] FromHex(string hexString)
        {
            int resultLen = hexString.Length / 2;
            byte[] result = new byte[resultLen];
            for (int h = 0, ptr = 0; h < resultLen; h++, ptr += 2)
            {
                result[h] = Convert.ToByte(hexString.Substring(ptr, 2), 16);
            }
            return result;
        }

        public static bool AreEqual(byte[] left, byte[] rigth)
        {
            if (left == rigth) return true; // same object
            if (left == null || rigth == null) return false; // one side are null
            if (left.Length != rigth.Length) return false; // one side is larger

            for (int i = 0; i < left.Length; i++)
            {
                if (left[i] != rigth[i]) return false; // one byte different
            }
            return true; // arrays are equal
        }

        public static byte[] Concat(byte[] left, byte[] rigth)
        {
            var result = new byte[left.Length + rigth.Length];
            Buffer.BlockCopy(left, 0, result, 0, left.Length);
            Buffer.BlockCopy(rigth, 0, result, left.Length, rigth.Length);
            return result;
        }
    }
}
