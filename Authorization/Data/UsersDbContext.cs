using Authorization.Models;
using Microsoft.EntityFrameworkCore;

namespace Authorization.Data
{
    public class UsersDbContext: DbContext
    {
        public UsersDbContext(DbContextOptions<UsersDbContext> options) : base(options)
        {

        }

        public DbSet<User> Users { get; set; }
    }
}
