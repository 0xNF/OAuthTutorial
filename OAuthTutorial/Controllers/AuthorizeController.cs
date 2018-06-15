using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OAuthTutorial.Data;
using OAuthTutorial.Models;
using OAuthTutorial.Models.AuthorizeViewModels;
using OAuthTutorial.Models.OAuth;

namespace OAuthTutorial.Controllers {

    [Route("/authorize/")]
    public class AuthorizeController : Controller {

        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public AuthorizeController(ApplicationDbContext context, UserManager<ApplicationUser> userManager) {
            _context = context;
            _userManager = userManager;
        }

        public async Task<IActionResult> Index() {
            OpenIdConnectRequest request = HttpContext.GetOpenIdConnectRequest();
            OAuthClient client = await _context.ClientApplications.Where(x => x.ClientId == request.ClientId).FirstOrDefaultAsync();
            if (client == null) {
                return NotFound();
            }

            AuthorizeViewModel vm = new AuthorizeViewModel() {
                ClientId = client.ClientId,
                ClientDescription = client.ClientDescription,
                ClientName = client.ClientName,
                RedirectUri = request.RedirectUri,
                ResponseType = request.ResponseType,
                Scopes = String.IsNullOrWhiteSpace(request.Scope) ? new string[0] : request.Scope.Split(' '),
                State = request.State
            };
            return View(vm);
        }

        [HttpPost("deny")]
        public async Task<IActionResult> Deny() {
            return LocalRedirect("/");
        }

        [HttpPost("accept")]
        public async Task<IActionResult> Accept() {
            ApplicationUser au = await _userManager.GetUserAsync(HttpContext.User);
            if (au == null) {
                return LocalRedirect("/error");
            }
            OpenIdConnectRequest request = HttpContext.GetOpenIdConnectRequest();
            AuthorizeViewModel avm = await FillFromRequest(request);
            if (avm == null) {
                return LocalRedirect("/error");
            }
            AuthenticationTicket ticket = TicketCounter.MakeClaimsForInteractive(au, avm);
            Microsoft.AspNetCore.Mvc.SignInResult sr = SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            return sr;
        }

        private async Task<AuthorizeViewModel> FillFromRequest(OpenIdConnectRequest OIDCRequest) {
            string clientId = OIDCRequest.ClientId;
            OAuthClient client = await _context.ClientApplications.FindAsync(clientId);
            if (client == null) {
                return null;
            }
            else {
                // Get the Scopes for this application from the query - disallow duplicates
                ICollection<OAuthScope> scopes = new HashSet<OAuthScope>();
                if (!String.IsNullOrWhiteSpace(OIDCRequest.Scope)) {
                    foreach (string s in OIDCRequest.Scope.Split(' ')) {
                        if (OAuthScope.NameInScopes(s)) {
                            OAuthScope scope = OAuthScope.GetScope(s);
                            if (!scopes.Contains(scope)) {
                                scopes.Add(scope);
                            }
                        }
                        else {
                            return null;
                        }
                    }
                }

                AuthorizeViewModel avm = new AuthorizeViewModel() {
                    ClientId = OIDCRequest.ClientId,
                    ResponseType = OIDCRequest.ResponseType,
                    State = OIDCRequest.State,
                    Scopes = String.IsNullOrWhiteSpace(OIDCRequest.Scope) ? new string[0] : OIDCRequest.Scope.Split(' '),
                    RedirectUri = OIDCRequest.RedirectUri
                };

                return avm;
            }
        }



    }
}
