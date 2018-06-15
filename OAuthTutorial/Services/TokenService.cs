using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OAuthTutorial.Data;
using OAuthTutorial.Models;
using OAuthTutorial.Models.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuthTutorial.Services {
    public class TokenService {

        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public TokenService(ApplicationDbContext context, UserManager<ApplicationUser> userManager) {
            _context = context;
            _userManager = userManager;
        }

        public async Task WriteNewTokenToDatabase(string client_id, Token token, ClaimsPrincipal user = null) {
            if (String.IsNullOrWhiteSpace(client_id) || token == null || String.IsNullOrWhiteSpace(token.GrantType) || String.IsNullOrWhiteSpace(token.Value)) {
                return;
            }

            OAuthClient client = await _context.ClientApplications.Include(x => x.Owner).Include(x => x.UserApplicationTokens).Where(x => x.ClientId == client_id).FirstOrDefaultAsync();
            if (client == null) {
                return;
            }

            // Handling Client Creds
            if (token.GrantType == OpenIdConnectConstants.GrantTypes.ClientCredentials) {
                List<Token> OldClientCredentialTokens = client.UserApplicationTokens.Where(x => x.GrantType == OpenIdConnectConstants.GrantTypes.ClientCredentials).ToList();
                foreach (Token old in OldClientCredentialTokens) {
                    _context.Entry(old).State = EntityState.Deleted;
                    client.UserApplicationTokens.Remove(old);
                }
                client.UserApplicationTokens.Add(token);
                _context.Update(client);
                await _context.SaveChangesAsync();
            }
            // Handling the other flows
            else if (token.GrantType == OpenIdConnectConstants.GrantTypes.Implicit || token.GrantType == OpenIdConnectConstants.GrantTypes.AuthorizationCode || token.GrantType == OpenIdConnectConstants.GrantTypes.RefreshToken) {
                if (user == null) {
                    return;
                }
                ApplicationUser au = await _userManager.GetUserAsync(user);
                if (au == null) {
                    return;
                }

                // These tokens also require association to a specific user
                IEnumerable<Token> OldTokensForGrantType = client.UserApplicationTokens.Where(x => x.GrantType == token.GrantType && x.TokenType == token.TokenType).Intersect(au.UserClientTokens).ToList();
                foreach (Token old in OldTokensForGrantType) {
                    _context.Entry(old).State = EntityState.Deleted;
                    client.UserApplicationTokens.Remove(old);
                    au.UserClientTokens.Remove(old);
                }
                client.UserApplicationTokens.Add(token);
                au.UserClientTokens.Add(token);
                _context.ClientApplications.Update(client);
                _context.Users.Update(au);
                await _context.SaveChangesAsync();
            }
        }
    }
}
