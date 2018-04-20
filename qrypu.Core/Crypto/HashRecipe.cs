/*
 * (C) 2018 José Hurtado
 * 
 * EN: Serialized hash computing like Sha256d (or double hash Sha256)
 * ES: Cálculo serializado de hash como Sha256d (o doble hash Sha256)
 * 
 * Licencia: para este archivo se aplica: https://opensource.org/licenses/MIT
 */
namespace qrypu.Core.Crypto
{
    using System;
    using System.Collections.Generic;

    public class HashRecipe
    {
        public delegate byte[] RecipeComputeHash(byte[] data);
        public RecipeComputeHash ComputeHash { get; private set; }

        private ICryptoHash[] _recipe;

        /// <summary>
        /// EN: Creates a hash recipe without hash algorithms
        /// </summary>
        public HashRecipe()
        {
            this._recipe = new ICryptoHash[] { };
            ConfigComputing();
        }

        /// <summary>
        /// EN: Creates a hash recipe with a list of hash algorithms
        /// </summary>
        /// <param name="recipe">EN: List of hash algorithms</param>
        public HashRecipe(CryptoHashName[] recipe)
        {
            if (recipe == null || recipe.Length < 1)
                throw new ArgumentException();

            this._recipe = new ICryptoHash[recipe.Length];
            for (int h = 0; h < recipe.Length; h++)
            {
                this._recipe[h] = CryptoHashFactory.Create(recipe[h]);
            }
            ConfigComputing();
        }

        /// <summary>
        /// EN: Add a new algorithm to recipe. Note: the best way is to configure recipe from constructor.
        /// </summary>
        /// <param name="hashAlgorithm">EN: Algorithm to add</param>
        public void Add(CryptoHashName hashAlgorithm)
        {
            var newRecipe = new List<ICryptoHash>(this._recipe);
            newRecipe.Add(CryptoHashFactory.Create(hashAlgorithm));
            this._recipe = newRecipe.ToArray();
            ConfigComputing();
        }

        /// <summary>
        /// EN: Config best methos to compute serialized hash recipe.
        /// </summary>
        private void ConfigComputing()
        {
            int length = this._recipe.Length;
            if (length == 1)
                ComputeHash = ComputeHashOnce;
            else if (length == 2)
                ComputeHash = ComputeHashTwice;
            else
                ComputeHash = ComputeHashFor;
        }

        /// <summary>
        /// EN: Optimized computing with only one hash to compute
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>Hash</returns>
        private byte[] ComputeHashOnce(byte[] data)
        {
            return this._recipe[0].Compute(data);
        }

        /// <summary>
        /// EN: Optimized computing with two serialized hash to compute
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>Hash</returns>
        private byte[] ComputeHashTwice(byte[] data)
        {
            return this._recipe[1].Compute(this._recipe[0].Compute(data));
        }

        /// <summary>
        /// EN: Computing for any number o serialized hashes to compute over data
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>Hash</returns>
        private byte[] ComputeHashFor(byte[] data)
        {
            byte[] result = data;
            int length = this._recipe.Length;
            for (int h = 0; h < length; h++)
            {
                result = this._recipe[h].Compute(result);
            }
            return result;
        }
    }
}