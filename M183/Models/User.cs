using System.ComponentModel.DataAnnotations;

namespace M183.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public bool IsAdmin { get; set; }

        public string? TwoFactorSecret { get; set; } 
        public bool IsTwoFactorEnabled { get; set; } = false; 

    }
}
