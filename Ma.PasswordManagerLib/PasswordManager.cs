using System.Linq;
using System.Security.Cryptography;

namespace Ma.PasswordManagerLib
{
    public class PasswordManager
    {
        private int saltSize = 32;

        /// <summary>
        /// Generate hash and salt for password
        /// </summary>
        /// <param name="passwordInput">Password to generate from</param>
        /// <returns>Hash and salt of password</returns>
        public Password GeneratePassword(string passwordInput)
        {
            using (Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(passwordInput, saltSize))
            {
                Password password = new Password();
                password.Salt = deriveBytes.Salt;
                password.Hash = deriveBytes.GetBytes(32);

                return password;
            }
        }

        /// <summary>
        /// Check if input password corresponds to generated password
        /// </summary>
        /// <param name="passwordInput">Password to check</param>
        /// <param name="password">Existing hashed password</param>
        /// <returns>True if input password is correct/Flase otherwise</returns>
        public bool CheckPassword(string passwordInput, Password password)
        {
            using (Rfc2898DeriveBytes deriveBytes = 
                new Rfc2898DeriveBytes(passwordInput, password.Salt))
            {
                return deriveBytes.GetBytes(saltSize).SequenceEqual(password.Hash);
            }
        }
    }
}
