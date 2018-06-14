using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using OAuthTutorial.Models.OAuth;

namespace OAuthTutorial.Models
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {
        /* The list of tokens that have been issued for a given user, across all applications */
        public List<Token> UserClientTokens { get; set; } = new List<Token>();

        /* The list of client applications a user has created. This is not the same as the UserClientTokens list. */
        public List<OAuthClient> UsersOAuthClients { get; set; } = new List<OAuthClient>();

    }
}
