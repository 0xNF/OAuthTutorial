using System;
using Microsoft.AspNetCore.Authorization;

namespace OAuthTutorial.Policies {
    public class HasScopeRequirement : IAuthorizationRequirement {

        public string Issuer { get; set; }
        public string Scope { get; set; }

        public HasScopeRequirement(string scope, string issuer) {
            Scope = scope ?? throw new ArgumentNullException(nameof(scope));
            Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        }
    }
}
