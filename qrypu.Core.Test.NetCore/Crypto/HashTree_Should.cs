using Microsoft.VisualStudio.TestTools.UnitTesting;
using qrypu.Core.Crypto;
using qrypu.Core.Test.NetCore.Common;
using System.Security.Cryptography;
using System.Text;

namespace qrypu.Core.Test.NetCore.Crypto
{
    [TestClass]
    public class HashTree_Should
    {
        [TestMethod]
        public void Compute_Unbalanced_Sha256d()
        {
            var hasher = SHA256.Create();
            var nodes = new byte[][]
            {
                /* A */ hasher.ComputeHash(Encoding.UTF8.GetBytes("La ciudad y los perros")),
                /* B */ hasher.ComputeHash(Encoding.UTF8.GetBytes("La Casa Verde")),
                /* C */ hasher.ComputeHash(Encoding.UTF8.GetBytes("Conversación en La Catedral")),
                /* D */ hasher.ComputeHash(Encoding.UTF8.GetBytes("Pantaleón y las visitadoras")),
                /* E */ hasher.ComputeHash(Encoding.UTF8.GetBytes("La tía Julia y el Escribidor"))
            };

            // Manual computing
            // levels = 3;   ceil(log2(5))

            // 4th level, 5 nodes, need balance: rigth (3)
            var hashA = hasher.ComputeHash(hasher.ComputeHash(nodes[0]));
            var hashB = hasher.ComputeHash(hasher.ComputeHash(nodes[1]));
            var hashC = hasher.ComputeHash(hasher.ComputeHash(nodes[2]));
            var hashD = hasher.ComputeHash(hasher.ComputeHash(nodes[3]));
            var hashE = hasher.ComputeHash(hasher.ComputeHash(nodes[4]));
            var hashX4 = hasher.ComputeHash(hasher.ComputeHash(hashA)); // balance
            var hashA_B = TestUtils.Concat(hashA, hashB);
            var hashC_D = TestUtils.Concat(hashC, hashD);
            var hashE_X4 = TestUtils.Concat(hashE, hashX4);

            // 3th level, 3 nodes, need balance: left (2)
            hashA_B = hasher.ComputeHash(hasher.ComputeHash(hashA_B));
            hashC_D = hasher.ComputeHash(hasher.ComputeHash(hashC_D));
            hashE_X4 = hasher.ComputeHash(hasher.ComputeHash(hashE_X4));
            var hashX3 = hasher.ComputeHash(hasher.ComputeHash(hashE_X4)); // balance
            var hashX3_A_B = TestUtils.Concat(hashX3, hashA_B);
            var hashC_D_E_X4 = TestUtils.Concat(hashC_D, hashE_X4);

            // 2nd level, 2 nodes, without balance
            hashX3_A_B = hasher.ComputeHash(hasher.ComputeHash(hashX3_A_B));
            hashC_D_E_X4 = hasher.ComputeHash(hasher.ComputeHash(hashC_D_E_X4));
            var hashROOT = TestUtils.Concat(hashX3_A_B, hashC_D_E_X4);

            // 1st level, 1 node, only hash
            hashROOT = hasher.ComputeHash(hasher.ComputeHash(hashROOT));

            // Computing map:
            //                         ROOT
            //               +-----------+-----------+
            //             X3_A_B                C_D_E_X4
            //         +-----+-----+           +-----+-----+
            //   (X3) E_X4'       A_B         C_D         E_X4
            //                  +--+--+     +--+--+     +--+--+
            //                  A     B     C     D     E     A' (X4)

            var tree = new HashTree();
            tree.HashRecipe.Add(CryptoHashName.Sha256);
            tree.HashRecipe.Add(CryptoHashName.Sha256);
            tree.Nodes.AddRange(nodes);
            tree.ComputeRoot();

            Assert.IsTrue(TestUtils.AreEqual(hashROOT, tree.Root));
            System.Diagnostics.Debug.WriteLine("Time: {0}ms", tree.LastComputeEllapsed);
        }

        [TestMethod]
        public void Compute_Balanced_Sha256d()
        {
            var hasher = SHA256.Create();
            var nodes = new byte[][]
            {
                /* A */ hasher.ComputeHash(Encoding.UTF8.GetBytes("La ciudad y los perros")),
                /* B */ hasher.ComputeHash(Encoding.UTF8.GetBytes("Conversación en La Catedral")),
                /* C */ hasher.ComputeHash(Encoding.UTF8.GetBytes("Pantaleón y las visitadoras")),
                /* D */ hasher.ComputeHash(Encoding.UTF8.GetBytes("La tía Julia y el Escribidor"))
            };

            // Manual computing
            // levels = 2;   ceil(log2(4))

            // 3th level, 4 nodes, without balance
            var hashA = hasher.ComputeHash(hasher.ComputeHash(nodes[0]));
            var hashB = hasher.ComputeHash(hasher.ComputeHash(nodes[1]));
            var hashC = hasher.ComputeHash(hasher.ComputeHash(nodes[2]));
            var hashD = hasher.ComputeHash(hasher.ComputeHash(nodes[3]));
            var hashA_B = TestUtils.Concat(hashA, hashB);
            var hashC_D = TestUtils.Concat(hashC, hashD);

            // 2th level, 2 nodes, without complement
            hashA_B = hasher.ComputeHash(hasher.ComputeHash(hashA_B));
            hashC_D = hasher.ComputeHash(hasher.ComputeHash(hashC_D));
            var hashROOT = TestUtils.Concat(hashA_B, hashC_D);

            // 1st level, 1 node, only hash
            hashROOT = hasher.ComputeHash(hasher.ComputeHash(hashROOT));

            // Computing map:
            //            ROOT
            //       +-----+-----+
            //      A_B         C_D
            //    +--+--+     +--+--+
            //    A     B     C     D

            var tree = new HashTree();
            tree.HashRecipe.Add(CryptoHashName.Sha256);
            tree.HashRecipe.Add(CryptoHashName.Sha256);
            tree.Nodes.AddRange(nodes);
            tree.ComputeRoot();

            Assert.IsTrue(TestUtils.AreEqual(hashROOT, tree.Root));
            System.Diagnostics.Debug.WriteLine("Time: {0}ms", tree.LastComputeEllapsed);
        }
    }
}
