using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using OAuthTutorial.Models;
using OAuthTutorial.Models.AuthorizeViewModels;
using OAuthTutorial.Models.OAuth;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace OAuthTutorial.Providers {

    public static class TicketCounter {

        public static AuthenticationTicket MakeClaimsForClientCredentials(string clientId) {
            ClaimsIdentity identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme, OpenIdConnectConstants.Claims.Name, OpenIdConnectConstants.Claims.Role);

            identity.AddClaim(
                new Claim(OpenIdConnectConstants.Claims.Subject, clientId)
                    .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken));


            // We serialize the grant_type so we can user discriminate rate-limits. AuthorizationCode grants typically have the highest rate-limit allowance
            identity.AddClaim(
                  new Claim("grant_type", OpenIdConnectConstants.GrantTypes.ClientCredentials)
                      .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken));

            // We serialize the client_id so we can monitor for usage patterns of a given app, and also to allow for app-based token revokes.
            identity.AddClaim(
                    new Claim("client_id", clientId)
                        .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken));


            AuthenticationTicket ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), new AuthenticationProperties(), OpenIdConnectServerDefaults.AuthenticationScheme);

            // In our implementation, an access token is valid for a single hour.
            return ticket;
        }

        public static AuthenticationTicket MakeClaimsForInteractive(ApplicationUser user, AuthorizeViewModel authorizeViewModel) {
            /*
             *  If you want to issue an OpenId Token, the spec for which is available at https://openid.net/connect/
             *  Then in each of the SetDestinations, add a reference to OpenIdConnect.Destinations.IdentityToken, like so:
             *  
             *  new Claim("grant_type", OpenIdConnectConstants.GrantTypes.AuthorizationCode)
             *         .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken, OpenIdConnectConstants.Destinations.IdentityToken));
             *         
             *   This ensures that the claims you are concerned about will be placed into the Identity Token, which other services may access.
             */
            ClaimsIdentity identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme, OpenIdConnectConstants.Claims.Name, OpenIdConnectConstants.Claims.Role);

            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id).SetDestinations(OpenIdConnectConstants.Destinations.AccessToken));
            identity.AddClaim(new Claim(ClaimTypes.Name, user.NormalizedUserName).SetDestinations(OpenIdConnectConstants.Destinations.AccessToken));
            identity.AddClaim(new Claim("AspNet.Identity.SecurityStamp", user.SecurityStamp).SetDestinations(OpenIdConnectConstants.Destinations.AccessToken));

            // We serialize the user_id so we can determine which user the caller of this token is
            identity.AddClaim(
                    new Claim(OpenIdConnectConstants.Claims.Subject, user.Id)
                        .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken));

            // We serialize the grant_type so we can user discriminate rate-limits. AuthorizationCode grants typically have the highest rate-limit allowance
            if (authorizeViewModel.ResponseType == OpenIdConnectConstants.ResponseTypes.Code) {
                identity.AddClaim(
                   new Claim("grant_type", OpenIdConnectConstants.GrantTypes.AuthorizationCode)
                       .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken));
            }
            else if (authorizeViewModel.ResponseType == OpenIdConnectConstants.ResponseTypes.Token) {
                identity.AddClaim(
                   new Claim("grant_type", OpenIdConnectConstants.GrantTypes.Implicit)
                       .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken));
            }

            // We serialize the client_id so we can monitor for usage patterns of a given app, and also to allow for app-based token revokes.
            identity.AddClaim(
                    new Claim("client_id", authorizeViewModel.ClientId)
                        .SetDestinations(OpenIdConnectConstants.Destinations.AccessToken));


            AuthenticationTicket ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), new AuthenticationProperties(), OpenIdConnectServerDefaults.AuthenticationScheme);

            ICollection<string> scopesToAdd = new List<string>() {
                /* If  you've chosen to add an OpenId token to your destinations, be sure to include the OpenIdCOnnectConstants.Scopes.OpenId in this list */
                //OpenIdConnectConstants.Scopes.OpenId, // Lets our requesting clients know that an OpenId Token was generated with the original request.
            };

            if (authorizeViewModel.ResponseType == OpenIdConnectConstants.ResponseTypes.Code) {
                scopesToAdd.Add(OpenIdConnectConstants.Scopes.OfflineAccess); //Gives us a RefreshToken, only do this if we're following the `Authorization Code` flow. For `Implicit Grant`, we don't supply a refresh token.    
            }
            foreach (string s in authorizeViewModel.Scopes) {
                if (OAuthScope.NameInScopes(s)) {
                    scopesToAdd.Add(s);
                }
            }

           ticket.SetScopes(scopesToAdd);

            return ticket;
        }
    }
}