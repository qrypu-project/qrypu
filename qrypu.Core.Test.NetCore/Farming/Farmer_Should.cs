﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using qrypu.Core.Crypto;
using qrypu.Core.Farming;
using System.Text;

namespace qrypu.Core.Test.NetCore.Mining
{
    [TestClass]
    public class Farmer_Should
    {
        [TestMethod]
        public void ComputeNonce_Tail_LessThan_4_Sha256()
        {
            var clearText = "Monseñor Myriel no tenía bienes. Su hermana cobraba una renta vitalicia de quinientos francos y monseñor Myriel recibía del Estado, como obispo, una asignación de quince mil francos.";
            var clearData = Encoding.UTF8.GetBytes(clearText);

            var mineConfig = new FarmingConfig()
            {
                NoncePosition = FarmingNoncePosition.Tail,
                NonceLength = 4,
                NonceInData = false,
                Challenge = FarmingBytes.LessOrEqualThan,
                ChallengeValue = FarmingBytes.Unpack(0x1EFFFFFF),
                HashRecipe = new [] { CryptoHashName.Sha256 }
            };
            var mineInfo = Farmer.Compute(clearData, mineConfig);

            // Check valid hash after mining
            Assert.IsTrue(mineInfo.HashCount > 0);
            Assert.IsTrue(mineInfo.Hash[0] == 0);  // Fist byte in hash is zero
            Assert.IsTrue(mineInfo.Hash[1] == 0);  // Second byte in hash is zero

            // Check nonce recomputing hash from data
            var checkInfo = Farmer.CheckNonce(clearData, mineInfo.Nonce, mineConfig);
            Assert.IsTrue(Common.TestUtils.AreEqual(mineInfo.Nonce, checkInfo.Nonce));
        }

        [TestMethod]
        public void ComputeNonce_Head_StartsWith_8_Recipe()
        {
            var clearText = "Monseñor Myriel no tenía bienes. Su hermana cobraba una renta vitalicia de quinientos francos y monseñor Myriel recibía del Estado, como obispo, una asignación de quince mil francos.";
            var clearData = Encoding.UTF8.GetBytes(clearText);

            var mineConfig = new FarmingConfig()
            {
                NoncePosition = FarmingNoncePosition.Head,
                NonceLength = 8,
                NonceInData = true,
                Challenge = FarmingBytes.StartsWith,
                ChallengeValue = new byte[] { 0x12, 0x34 },
                HashRecipe = new[] { CryptoHashName.Groestl384, CryptoHashName.Skein224, CryptoHashName.Blake256 }
            };
            var mineInfo = Farmer.Compute(clearData, mineConfig);

            // Check valid hash after mining
            Assert.IsTrue(mineInfo.HashCount > 0);
            Assert.IsTrue(mineInfo.Hash[0] == 0x12); 
            Assert.IsTrue(mineInfo.Hash[1] == 0x34); 

            // Check nonce recomputing hash from data
            var checkInfo = Farmer.CheckNonce(clearData, mineInfo.Nonce, mineConfig);
            Assert.IsTrue(Common.TestUtils.AreEqual(mineInfo.Nonce, checkInfo.Nonce));
        }
    }
}