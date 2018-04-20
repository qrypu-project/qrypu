/*
 * (C) 2018 José Hurtado
 * 
 * ES: Variante de Merkle Tree. Puede usar cualquier "receta" de hash y otra forma de balancear.
 * EN: Variant of Merkle Tree. It can usae any "recipe" of hash and another way to balance.
 * 
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;

    /// <summary>
    /// EN:
    /// Balance procedure:
    ///  - Level number is even, then copy hash(left) to the right side.
    ///  - Level number is odd, then copy hash(right) to the left side.
    /// ES:
    /// Forma de balance:
    ///  - Nivel es par, entonces copiar hash(izquierda) al lado derecho.
    ///  - Nivel es impar, entonces copiar hash(derecha) al lado izquierdo.
    /// 
    /// EN: Example for five nodes, four levels:
    /// ES: Ejemplo con cinco nodos, cuatro niveles:
    /// 
    /// L1                        ROOT
    ///                 +-----------+-----------+
    /// L2            X3_A_B                C_D_E_X4
    ///           +-----+-----+           +-----+-----+
    /// L3  (X3) E_X4'       A_B         C_D         E_X4
    ///                    +--+--+     +--+--+     +--+--+
    /// L4                 A     B     C     D     E     A' (X4)
    /// 
    /// EN: L4 is even, X4 = hash(A). L3 is odd, X3 = hash(E_X4)
    /// ES: L4 es par, X4 = hash(A). L3 es impar, X3 = hash(E_X4)
    /// </summary>
    public class HashTree
    {
        public List<byte[]> Nodes { get; private set; }
        public HashRecipe HashRecipe { get; set; }
        public byte[] Root { get; private set; }
        public long LastComputeEllapsed { get; private set; }

        public HashTree()
        {
            this.Nodes = new List<byte[]>();
            this.HashRecipe = new HashRecipe();
            this.Root = null;
            this.LastComputeEllapsed = -1;
        }

        /// <summary>
        /// EN: Compute all tree and set Root hash
        /// ES: Calcula todo el árbol y establece el hash de la Raiz
        /// 
        /// Test/Pruebas: OurBlocks.Core.Test.Common.HashTree_Should.CalcRootFiveNodes
        /// </summary>
        public void ComputeRoot()
        {
            this.Root = null;
            this.LastComputeEllapsed = 0;
            if (this.HashRecipe == null)
                throw new InvalidOperationException();

            var watch = new Stopwatch();
            try
            {
                var nodes = this.Nodes;
                var nodeCount = nodes.Count;

                if (nodeCount == 0) return;
                int level = (int)Math.Ceiling(Math.Log(nodeCount) / Math.Log(2));

                while (nodeCount > 1)
                {
                    nodes = ComputeLevel(nodes, level);
                    nodeCount = nodes.Count;
                    level--;
                }

                // EN: Compute root hash
                // ES: Calcula el hash de la Raiz
                HashNodes(nodes);
                this.Root = nodes[0];
            }
            finally
            {
                watch.Stop();
                this.LastComputeEllapsed = watch.ElapsedMilliseconds;
            }
        }

        /// <summary>
        /// EN:
        /// Concatenate nodes in pairs.
        /// If there is an odd number of nodes, then balance as explained in class.<see cref="HashTree"/>
        /// ES:
        /// Concatena nodos en pares.
        /// Si hay un número impar de nodos se balancea como se emplica en la clase. <see cref="HashTree"/>
        /// </summary>
        /// <param name="nodes">
        /// EN: Nodes to concatenate in pairs
        /// ES: Nodos a concatenar en pares
        /// </param>
        /// <param name="level">
        /// EN: Level. It's important to decide how to balance
        /// ES: Nivel. Es importante para decidir como se aplica el balance
        /// </param>
        /// <returns>Nodes concatenated</returns>
        private List<byte[]> ComputeLevel(List<byte[]> nodes, int level)
        {
            HashNodes(nodes);
            var nodeCount = nodes.Count;

            // EN: Balance nodes if needed
            // ES: Balancea nodos si es necesario
            var needBalance = (nodeCount % 2) != 0;
            if (needBalance)
            {
                if ((level % 2) == 0) // EN: left balance. ES: balanceo por la izquierda
                    nodes.Insert(0, this.HashRecipe.ComputeHash(nodes[nodeCount - 1]));
                else // EN: rigth balance. ES: balanceo por la derecha
                    nodes.Add(this.HashRecipe.ComputeHash(nodes[0]));
            }

            var result = new List<byte[]>();
            for (int s = 0; s < nodeCount; s += 2)
            {
                var hashL = nodes[s];
                var hashR = nodes[s + 1];

                // EN: Creates new nodes through pair concatenation
                // ES: Crear nuevos nodos mediante concatenación de pares
                var newNode = new byte[hashL.Length + hashR.Length];
                Buffer.BlockCopy(hashL, 0, newNode, 0, hashL.Length);
                Buffer.BlockCopy(hashR, 0, newNode, hashL.Length, hashR.Length);

                result.Add(newNode);
            }

            return result;
        }

        /// <summary>
        /// EN: Compute hash for all the nodes
        /// ES: Calcula el hash para todos los nodos
        /// </summary>
        /// <param name="nodes">
        /// EN: Nodes to process
        /// ES: Nodos para procesar
        /// </param>
        private void HashNodes(List<byte[]> nodes)
        {
            var nodeCount = nodes.Count;
            for (int s = 0; s < nodeCount; s++)
            {
                nodes[s] = this.HashRecipe.ComputeHash(nodes[s]);
            }
        }
    }
}