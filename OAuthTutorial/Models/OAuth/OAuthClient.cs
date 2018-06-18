using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthTutorial.Models.OAuth {
    public class OAuthClient {

        /* EntityFramework classes that have an Id field that deviates from the auto-detectable formats need to have that field annotated with [Key] */
        [Key]
        public string ClientId { get; set; }

        /* Each App needs a Client Secret, but it is assigned at creation */
        [Required]
        public string ClientSecret { get; set; }

        /* Each App Needs an Owner, which will be assigned at creation. This is also a Foreign Key to the Users table. */
        [Required]
        [ForeignKey("Id")]
        public ApplicationUser Owner { get; set; }

        /* This field, combined with the RedirectURI.OAuthClient field, lets EntityFramework know that this is a (1 : Many} mapping */
        public List<RedirectURI> RedirectURIs { get; set; } = new List<RedirectURI>();

        /*  Like above, this notifies EntityFramework of another (1 : Many) mapping */
        public List<Token> UserApplicationTokens { get; set; } = new List<Token>();

        /* A Rate limit object for our client - separate from any rate limits applied to the users of this application. */
        public RateLimit RateLimit { get; set; }

        /* A rate limit objects for tokens issued to this client - usually null
        * but if a client has been granted special overrides, the limits specified here will be issued to the tokens, 
        * as opposed to the default grant_type token limits.
        * This allows us to offer specific applications increaed overall limtis, and incresed per-user limits, if so desired. */
        public RateLimit SubordinateTokenLimits { get; set; }

        [Required]
        [MinLength(2)]
        [MaxLength(100)]
        public string ClientName { get; set; } // Each App needs a Name, which is submutted by the user at Creation

        [Required]
        [MinLength(1)]
        [MaxLength(300)]
        public string ClientDescription { get; set; } // Each App needs a Description, which is submitted by the Creation
    }
}
