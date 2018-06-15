using AspNet.Security.OpenIdConnect.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthTutorial.Providers
{
    public class OAuthProvider : OpenIdConnectServerProvider {


        public override Task MatchEndpoint(MatchEndpointContext context) {
            if (context.Options.AuthorizationEndpointPath.HasValue &&
                context.Request.Path.Value.StartsWith(context.Options.AuthorizationEndpointPath)) {
                context.MatchAuthorizationEndpoint();
            }
            return Task.CompletedTask;
        }


        #region Authorization Requests
        public override async Task ValidateAuthorizationRequest(ValidateAuthorizationRequestContext context) {
            base.ValidateAuthorizationRequest(context);
        }

        public override async Task ApplyAuthorizationResponse(ApplyAuthorizationResponseContext context) {
            base.ApplyAuthorizationResponse(context);
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
