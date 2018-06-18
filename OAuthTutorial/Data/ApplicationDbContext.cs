using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OAuthTutorial.Models;
using OAuthTutorial.Models.OAuth;

namespace OAuthTutorial.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser> {

        public DbSet<OAuthClient> ClientApplications { get; set; }
        public DbSet<Token> Tokens { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options) {
        }

        protected override void OnModelCreating(ModelBuilder builder) {
            base.OnModelCreating(builder);

            /* An OAuthClients name is unique among all other OAuthClients */
            builder.Entity<OAuthClient>()
                .HasAlternateKey(x => x.ClientName);

            /* When an AspNet User is deleted, delete their created OAuthClients */
            builder.Entity<OAuthClient>()
                .HasOne(x => x.Owner)
                .WithMany(x => x.UsersOAuthClients)
                .OnDelete(DeleteBehavior.Cascade);

            /* When an OAuthClient is deleted, delete its Rate Limits */
            builder.Entity<OAuthClient>()
                .HasOne(x => x.RateLimit)
                .WithOne(x => x.Client)
                .HasForeignKey<RateLimit>(x => x.ClientId)
                .OnDelete(DeleteBehavior.Cascade);

            /* When an OAuthClient is deleted, delete its Subordinate Rate Limit */
            builder.Entity<OAuthClient>()
                .HasOne(x => x.SubordinateTokenLimits)
                .WithOne(x => x.SubordinatedClient)
                .HasForeignKey<RateLimit>(x => x.SubordinatedClientId)
                .OnDelete(DeleteBehavior.Cascade);

            /* RWhen a Rate Limit is deleted, delete any Tokens that use this rate limit */
            builder.Entity<RateLimit>()
                .HasOne(x => x.Token)
                .WithOne(x => x.RateLimit)
                .OnDelete(DeleteBehavior.Cascade);

            /* When an AspNetUser is deleted, delete their tokens */
            builder.Entity<ApplicationUser>()
                .HasMany(x => x.UserClientTokens)
                .WithOne(y => y.User)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            /* When an OAuth Client is deleted, delete any Redirect URIs it used. */
            builder.Entity<RedirectURI>()
                .HasOne(x => x.OAuthClient)
                .WithMany(x => x.RedirectURIs)
                .HasForeignKey(x => x.OAuthClientId)
                .OnDelete(DeleteBehavior.Cascade);


            /* When an OAuth Client is deleted, delete any tokens it issued */
            builder.Entity<OAuthClient>()
                .HasMany(x => x.UserApplicationTokens)
                .WithOne(x => x.Client)
                .HasForeignKey(x => x.OAuthClientId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
