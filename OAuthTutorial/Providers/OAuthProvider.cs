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
            base.ValidateTokenRequest(context);
        }

        public override Task HandleTokenRequest(HandleTokenRequestContext context) {
            return base.HandleTokenRequest(context);
        }

        public override async Task ApplyTokenResponse(ApplyTokenResponseContext context) {
            base.ApplyTokenResponse(context);
        }
        #endregion

    }
}
