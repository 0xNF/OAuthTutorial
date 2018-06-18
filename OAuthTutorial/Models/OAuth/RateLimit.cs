using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OAuthTutorial.Models.OAuth {

    public class RateLimit {

        [Key]
        public int RateLimitId { get; set; } // Primary key for Entity Framework, because this will also be a database object
        public int? Limit { get; set; } // Nullable, so that a limit of 'null' may represent no limit at all.
        public TimeSpan? Window { get; set; } // The timespan of the rolling window. 

        
        [ForeignKey("TokenId")]
        public Token Token { get; set; }

        public string ClientId { get; set; }
        public OAuthClient Client { get; set; }

        public string SubordinatedClientId { get; set; }
        public OAuthClient SubordinatedClient { get; set; }

        public static RateLimit DefaultClientLimit =>
            new RateLimit() {
                Limit = 5, // 10_000
                Window = TimeSpan.FromHours(1),
            };

        public static RateLimit DefaultImplicitLimit => 
            new RateLimit() {
                Limit = 1, // 150
                Window = TimeSpan.FromHours(1)
            };

        public static RateLimit DefaultAuthorizationCodeLimit =>
            new RateLimit() {
                Limit = 500,
                Window = TimeSpan.FromHours(1)
            };
    }
}
