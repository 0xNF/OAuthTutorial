using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OAuthTutorial.Models.OAuth {
    public class Token {

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int TokenId { get; set; }

        /* How this token was created: 'token', 'authorization_code', 'client_credentials', 'refresh' */
        public string GrantType { get; set; }

        /* Access, Refresh */
        public string TokenType { get; set; }

        /* The raw value of a token. */
        public string Value { get; set; }

        /* Rate limit for this token, which is independant, but lower than, the rate limit of the client that its authenticated to. */
        public RateLimit RateLimit { get; set; } 

        /* Entity Framework Foreign Key Anchors for OAuth Clients */
        public string OAuthClientId { get; set; }
        public OAuthClient Client { get; set; }

        /* Entity Framework Foreign Key Anchors for Users */
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }
    }
}
