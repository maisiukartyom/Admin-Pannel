using System.ComponentModel.DataAnnotations;

namespace Authorization.Models
{
    public class User
    {   

        [Key]
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
        public DateTime Registered { get; set; }
        public DateTime LastLogin { get; set; }
        public bool isBanned { get; set; } = false;
    }
}
