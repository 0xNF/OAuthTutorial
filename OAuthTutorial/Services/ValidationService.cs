using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.EntityFrameworkCore;
using OAuthTutorial.Data;
using OAuthTutorial.Models.OAuth;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthTutorial.Services {
    public class ValidationService {

        private readonly ApplicationDbContext _context;

        public ValidationService(ApplicationDbContext context) {
            _context = context;
        }

        public async Task<bool> CheckClientIdIsValid(string client_id) {
            if (String.IsNullOrWhiteSpace(client_id)) {
                return false;
            }
            else {
                return await _context.ClientApplications.AnyAsync(x => x.ClientId == client_id);
            }
        }

        public async Task<bool> CheckClientIdAndSecretIsValid(string client_id, string client_secret) {
            if (String.IsNullOrWhiteSpace(client_id) || String.IsNullOrWhiteSpace(client_secret)) {
                return false;
            }
            else {
                // This could be an easy check, but the ASOS maintainer strongly recommends you to use a fixed-time string compare for client secrets.
                // This is trivially available in any .NET Core 2.1 or higher framework, but this is a 2.0 project, so we will leave that part out.
                // If you are on 2.1+, checkout the System.Security.Cryptography.CryptographicOperations.FixedTimeEquals() mehod,
                // available at https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptographicoperations.fixedtimeequals?view=netcore-2.1
                return await _context.ClientApplications.AnyAsync(x => x.ClientId == client_id && x.ClientSecret == client_secret);
            }
        }

        public async Task<bool> CheckRedirectURIMatchesClientId(string client_id, string redirect_uri) {
            if (String.IsNullOrWhiteSpace(client_id) || String.IsNullOrWhiteSpace(redirect_uri)) {
                return false;
            }
            return await _context.ClientApplications.Include(x => x.RedirectURIs).
                AnyAsync(x => x.ClientId == client_id &&
                    x.RedirectURIs.Any(y => y.URI == redirect_uri));
        }

        public async Task<bool> CheckRefreshTokenIsValid(string refresh) {
            if (String.IsNullOrWhiteSpace(refresh)) {
                return false;
            }
            else {
                return await _context.ClientApplications.Include(x => x.UserApplicationTokens).AnyAsync(x => x.UserApplicationTokens.Any(y => y.TokenType == OpenIdConnectConstants.TokenUsages.RefreshToken && y.Value == refresh));
            }
        }

        public async Task<bool> CheckScopesAreValid(string scope) {
            if (string.IsNullOrWhiteSpace(scope)) {
                return true; // Unlike the other checks, an empty scope is a valid scope. It just means the application has default permissions.
            }

            string[] scopes = scope.Split(' ');
            foreach (string s in scopes) {
                if (!OAuthScope.NameInScopes(s)) {
                    return false;
                }
            }
            return true;
        }
    }
}
