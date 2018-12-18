namespace PH.PicoCrypt2
{
    /// <summary>
    /// Random String Mode
    /// </summary>
    public enum RandomStringMode
    {
        /// <summary>
        /// Characters, numbers and symbols
        /// </summary>
        Full,

        /// <summary>
        /// Only chars
        /// </summary>
        CharactersOnly,

        /// <summary>
        /// Chars and numbers
        /// </summary>
        CharacterAndNumbers,

        /// <summary>
        /// Symbols and numbers
        /// </summary>
        SymbolsAndNumbers,
        
        /// <summary>
        /// Only symbols
        /// </summary>
        OnlySymbols,

        /// <summary>
        /// Only numbers
        /// </summary>
        OnlyNumbers
    }
}
