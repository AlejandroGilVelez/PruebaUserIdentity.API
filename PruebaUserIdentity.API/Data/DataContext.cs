using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PruebaUserIdentity.API.Models;

namespace PruebaUserIdentity.API.Data
{
    public class DataContext : IdentityDbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);            
        }

        public DbSet<User> TblUsers { get; set; }

        public DbSet<Role> TblRoles { get; set; }
    }
}
