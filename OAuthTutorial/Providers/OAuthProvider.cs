using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OAuthTutorial.Data;
using OAuthTutorial.Models.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuthTutorial.Providers
{
    public class OAuthProvider : OpenIdConnectServerProvider {

        private ValidationService VService;
        private TokenService TService;

        public override Task MatchEndpoint(MatchEndpointContext context) {
            if (context.Options.AuthorizationEndpointPath.HasValue &&
                context.Request.Path.Value.StartsWith(context.Options.AuthorizationEndpointPath)) {
                context.MatchAuthorizationEndpoint();
            }
            return Task.CompletedTask;
        }


        #region Authorization Requests
        public override async Task ValidateAuthorizationRequest(ValidateAuthorizationRequestContext context) {
            VService = context.HttpContext.RequestServices.GetRequiredService<ValidationService>();

            if (!context.Request.IsAuthorizationCodeFlow() && !context.Request.IsImplicitFlow()) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    description: "Only authorization code, refresh token, and token grant types are accepted by this authorization server."
                );
                return;
            }

            string clientid = context.ClientId;
            string rdi = context.Request.RedirectUri;
            string state = context.Request.State;
            string scope = context.Request.Scope;

            if (String.IsNullOrWhiteSpace(clientid)) {
                context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidClient,
                            description: "client_id cannot be empty"
                        );
                return;
            }
            else if (String.IsNullOrWhiteSpace(rdi)) {
                context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidClient,
                            description: "redirect_uri cannot be empty"
                        );
                return;
            }
            else if (!await VService.CheckClientIdIsValid(clientid)) {
                context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidClient,
                            description: "The supplied client id does not exist"
                        );
                return;
            }
            else if (!await VService.CheckRedirectURIMatchesClientId(clientid, rdi)) {
                context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidClient,
                            description: "The supplied redirect uri is incorrect"
                        );
                return;
            }
            else if (!await VService.CheckScopesAreValid(scope)) {
                context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "One or all of the supplied scopes are invalid"
                    );
                return;
            }

            context.Validate();

        }

        public override async Task ApplyAuthorizationResponse(ApplyAuthorizationResponseContext context) {
            if (!String.IsNullOrWhiteSpace(context.Error)) {
                return;
            }
            TService = context.HttpContext.RequestServices.GetRequiredService<TokenService>();
            ApplicationDbContext db = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
            ClaimsPrincipal claimsUser = context.HttpContext.User;
            // Implicit grant is the only flow that gets their token issued here.
            Token access = new Token() {
                GrantType = OpenIdConnectConstants.GrantTypes.Implicit,
                TokenType = OpenIdConnectConstants.TokenUsages.AccessToken,
                Value = context.AccessToken,
            };

            OAuthClient client = db.ClientApplications.First(x => x.ClientId == context.Request.ClientId);
            if (client == null) {
                return;
            }

            await TService.WriteNewTokenToDatabase(context.Request.ClientId, access, claimsUser);
        }
        #endregion


        #region Token Requests
        public override async Task ValidateTokenRequest(ValidateTokenRequestContext context) {

            VService = context.HttpContext.RequestServices.GetRequiredService<ValidationService>();

            // We only accept "authorization_code", "refresh", "token" for this endpoint.
            if (!context.Request.IsAuthorizationCodeGrantType()
                && !context.Request.IsRefreshTokenGrantType()
                && !context.Request.IsClientCredentialsGrantType()) {
                context.Reject(
                        error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                        description: "Only authorization code, refresh token, and token grant types are accepted by this authorization server."
                    );
            }

            string clientid = null;
            string clientsecret = null;
            string redirecturi = null;
            string code = null;
            string refreshtoken = null;

            // Validating the Authorization Code Token Request
            if (context.Request.IsAuthorizationCodeGrantType()) {
                clientid = context.ClientId;
                clientsecret = context.ClientSecret;
                code = context.Request.Code;
                redirecturi = context.Request.RedirectUri;

                if (String.IsNullOrWhiteSpace(clientid)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "client_id cannot be empty"
                          );
                    return;
                }
                else if (String.IsNullOrWhiteSpace(clientsecret)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "client_secret cannot be empty"
                          );
                    return;
                }
                else if (String.IsNullOrWhiteSpace(redirecturi)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "redirect_uri cannot be empty"
                          );
                    return;
                }
                else if (!await VService.CheckClientIdIsValid(clientid)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "The supplied client id was does not exist"
                          );
                    return;
                }
                else if (!await VService.CheckClientIdAndSecretIsValid(clientid, clientsecret)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "The supplied client secret is invalid"
                          );
                    return;
                }
                else if (!await VService.CheckRedirectURIMatchesClientId(clientid, redirecturi)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "The supplied redirect uri is incorrect"
                          );
                    return;
                }

                context.Validate();
                return;
            }
            // Validating the Refresh Code Token Request
            else if (context.Request.IsRefreshTokenGrantType()) {
                clientid = context.Request.ClientId;
                clientsecret = context.Request.ClientSecret;
                refreshtoken = context.Request.RefreshToken;

                if (String.IsNullOrWhiteSpace(clientid)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "client_id cannot be empty"
                          );
                    return;
                }
                else if (String.IsNullOrWhiteSpace(clientsecret)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "client_secret cannot be empty"
                          );
                    return;
                }
                else if (!await VService.CheckClientIdIsValid(clientid)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "The supplied client id does not exist"
                          );
                    return;
                }
                else if (!await VService.CheckClientIdAndSecretIsValid(clientid, clientsecret)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "The supplied client secret is invalid"
                          );
                    return;
                }
                else if (!await VService.CheckRefreshTokenIsValid(refreshtoken)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "The supplied refresh token is invalid"
                          );
                    return;
                }

                context.Validate();
                return;
            }
            // Validating Client Credentials Request, aka, 'token'
            else if (context.Request.IsClientCredentialsGrantType()) {
                clientid = context.ClientId;
                clientsecret = context.ClientSecret;


                if (String.IsNullOrWhiteSpace(clientid)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "client_id cannot be empty"
                          );
                    return;
                }
                else if (String.IsNullOrWhiteSpace(clientsecret)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "client_secret cannot be empty"
                          );
                    return;
                }
                else if (!await VService.CheckClientIdIsValid(clientid)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "The supplied client id does not exist"
                          );
                    return;
                }
                else if (!await VService.CheckClientIdAndSecretIsValid(clientid, clientsecret)) {
                    context.Reject(
                              error: OpenIdConnectConstants.Errors.InvalidClient,
                              description: "The supplied client secret is invalid"
                          );
                    return;
                }

                context.Validate();
                return;
            }
            else {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.ServerError,
                    description: "Could not validate the token request"
                );
                return;
            }
        }

        public override Task HandleTokenRequest(HandleTokenRequestContext context) {
            AuthenticationTicket ticket = null;
            // Handling Client Credentials
            if (context.Request.IsClientCredentialsGrantType()) {
                // If we do not specify any form of Ticket, or ClaimsIdentity, or ClaimsPrincipal, our validation will succeed here but fail later.
                // ASOS needs those to serialize a token, and without any, it fails because there's way to fashion a token properly. Check the ASOS source for more details.
                ticket = TicketCounter.MakeClaimsForClientCredentials(context.Request.ClientId);
                context.Validate(ticket);
                return Task.CompletedTask;
            }
            // Handling Authorization Codes
            else if (context.Request.IsAuthorizationCodeGrantType() || context.Request.IsRefreshTokenGrantType()) {
                ticket = context.Ticket;
                if (ticket != null) {
                    context.Validate(ticket);
                    return Task.CompletedTask;
                }
                else {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "User isn't valid"
                    );
                    return Task.CompletedTask;
                }

            }
            // Catch all error
            context.Reject(
                error: OpenIdConnectConstants.Errors.ServerError,
                description: "Could not validate the token request"
            );
            return Task.CompletedTask;
        }

        // Our Token Request was successful - we should write the returned values to the database.
        public override async Task ApplyTokenResponse(ApplyTokenResponseContext context) {
            if (context.Error != null) {

            }
            TService = context.HttpContext.RequestServices.GetRequiredService<TokenService>();
            ApplicationDbContext db = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
            OAuthClient client = await db.ClientApplications.FirstOrDefaultAsync(x => x.ClientId == context.Request.ClientId);
            if (client == null) {
                return;
            }

            // Implicit Flow Tokens are not returned from the `Token` group of methods - you can find them in the `Authorize` group.
            if (context.Request.IsClientCredentialsGrantType()) {
                // The only thing returned from a successful client grant is a single `Token`
                Token t = new Token() {
                    TokenType = OpenIdConnectConstants.TokenUsages.AccessToken,
                    GrantType = OpenIdConnectConstants.GrantTypes.ClientCredentials,
                    Value = context.Response.AccessToken,
                };

                await TService.WriteNewTokenToDatabase(context.Request.ClientId, t);
            }
            else if (context.Request.IsAuthorizationCodeGrantType()) {
                Token access = new Token() {
                    TokenType = OpenIdConnectConstants.TokenUsages.AccessToken,
                    GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode,
                    Value = context.Response.AccessToken,
                };
                Token refresh = new Token() {
                    TokenType = OpenIdConnectConstants.TokenUsages.RefreshToken,
                    GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode,
                    Value = context.Response.RefreshToken,
                };

                await TService.WriteNewTokenToDatabase(context.Request.ClientId, access, context.Ticket.Principal);
                await TService.WriteNewTokenToDatabase(context.Request.ClientId, refresh, context.Ticket.Principal);
            }
            else if (context.Request.IsRefreshTokenGrantType()) {
                Token access = new Token() {
                    TokenType = OpenIdConnectConstants.TokenUsages.AccessToken,
                    GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode,
                    Value = context.Response.AccessToken,
                };
                await TService.WriteNewTokenToDatabase(context.Request.ClientId, access, context.Ticket.Principal);
            }
        }
        #endregion

    }
}
