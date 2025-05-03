
using M183.Models;
using Microsoft.EntityFrameworkCore;

namespace M183.Data
{
    public class NewsAppContext : DbContext
    {
        public NewsAppContext(DbContextOptions<NewsAppContext> options) : base(options) { } 
        public DbSet<News> News { get; set; }
        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            new NewsAppInitializer(modelBuilder).Seed();
        }
    }
}
