using Microsoft.AspNetCore.Authentication;
using OAuthTutorial.Models;
using OAuthTutorial.Models.AuthorizeViewModels;

namespace OAuthTutorial.Providers {

    public static class TicketCounter {
        public static AuthenticationTicket MakeClaimsForClientCredentials(string clientId) {
            return null;
        }

        public static AuthenticationTicket MakeClaimsForInteractive(ApplicationUser user, AuthorizeViewModel authorizeViewModel) {
            return null;
        }
    }
}