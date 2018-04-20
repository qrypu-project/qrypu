using Microsoft.VisualStudio.TestTools.UnitTesting;
using qrypu.Core.Crypto;
using qrypu.Core.Test.NetCore.Common;
using System.Security.Cryptography;

namespace qrypu.Core.Test.NetCore.Crypto
{
    [TestClass]
    public class HashRecipe_Should
    {
        [TestMethod]
        public void Compute_AsSha256d()
        {
            var data = TestUtils.FromHex("416B5CDC9FE951BD361BD7ABFC120A5054758EBA88FDD68FD84E39D3B09AC25497D36B43CBE7B85A6A3CEBDA8DB4E5549C3EE51BB6FCB6AC1E");
            var sha256 = SHA256.Create();
            var expected = sha256.ComputeHash(sha256.ComputeHash(data));

            var recipe = new HashRecipe(new CryptoHashName[] { CryptoHashName.Sha256, CryptoHashName.Sha256 });
            var result = recipe.ComputeHash(data);

            Assert.IsTrue(TestUtils.AreEqual(expected, result));
        }

        [TestMethod]
        public void Compute_AnyRecipe()
        {
            var data = TestUtils.FromHex("416B5CDC9FE951BD361BD7ABFC120A5054758EBA88FDD68FD84E39D3B09AC25497D36B43CBE7B85A6A3CEBDA8DB4E5549C3EE51BB6FCB6AC1E");
            var step1 = SHA256.Create();
            var step2 = GroestlHashAlgorithm.Create(384);
            var step3 = SkeinHashAlgorithm.Create(224);
            var step4 = BlakeHashAlgorithm.Create(512);
            var step5 = SHA256.Create();
            var expected = step5.ComputeHash(step4.ComputeHash(step3.ComputeHash(step2.ComputeHash(step1.ComputeHash(data)))));

            var recipe = new HashRecipe(new CryptoHashName[]
            {
                CryptoHashName.Sha256,
                CryptoHashName.Groestl384,
                CryptoHashName.Skein224,
                CryptoHashName.Blake512,
                CryptoHashName.Sha256
            });
            var result = recipe.ComputeHash(data);

            Assert.IsTrue(TestUtils.AreEqual(expected, result));
        }

        [TestMethod]
        public void Support_AddAlgorithm()
        {
            var data = TestUtils.FromHex("416B5CDC9FE951BD361BD7ABFC120A5054758EBA88FDD68FD84E39D3B09AC25497D36B43CBE7B85A6A3CEBDA8DB4E5549C3EE51BB6FCB6AC1E");
            var step1 = SHA256.Create();
            var step2 = GroestlHashAlgorithm.Create(384);
            var step3 = SkeinHashAlgorithm.Create(224);
            var step4 = BlakeHashAlgorithm.Create(512);
            var step5 = SHA256.Create();
            var expected = step5.ComputeHash(step4.ComputeHash(step3.ComputeHash(step2.ComputeHash(step1.ComputeHash(data)))));

            var recipe = new HashRecipe();
            recipe.Add(CryptoHashName.Sha256);
            recipe.Add(CryptoHashName.Groestl384);
            recipe.Add(CryptoHashName.Skein224);
            recipe.Add(CryptoHashName.Blake512);
            recipe.Add(CryptoHashName.Sha256);
            var result = recipe.ComputeHash(data);

            Assert.IsTrue(TestUtils.AreEqual(expected, result));
        }
    }
}