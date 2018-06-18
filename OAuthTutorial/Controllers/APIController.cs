using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OAuthTutorial.Attributes;
using OAuthTutorial.Data;
using OAuthTutorial.Models;
using System.Threading.Tasks;

namespace OAuthTutorial.Controllers {

    [Route("/api/v1/")]
    public class APIController : Controller {

        private readonly ILogger _logger;
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public APIController(ILogger<ManageController> logger, ApplicationDbContext context, UserManager<ApplicationUser> userManager) {
            _logger = logger;
            _context = context;
            _userManager = userManager;
        }

        // Unauthenticated Methods - available to the public
        [HttpGet("hello")]
        public IActionResult Hello() {
            return Ok("Hello");
        }

        // Authenticated Methdos - only available to those with a valid Access Token
        // Unscoped Methods - Authenticated methods that do not require any specific Scope
        [RateLimit]
        [Authorize(AuthenticationSchemes = AspNet.Security.OAuth.Validation.OAuthValidationDefaults.AuthenticationScheme)]
        [HttpGet("clientcount")]
        public async Task<IActionResult> ClientCount() {
            return Ok("Client Count Get Request was successful but this endpoint is not yet implemented");
        }

        // Scoped Methods - Authenticated methods that require certain scopes
        [RateLimit]
        [Authorize(AuthenticationSchemes = AspNet.Security.OAuth.Validation.OAuthValidationDefaults.AuthenticationScheme, Policy = "user-read-birthdate")]
        [HttpGet("birthdate")]
        public IActionResult GetBirthdate() {
            return Ok("Birthdate Get Request was successful but this endpoint is not yet implemented");
        }

        [RateLimit]
        [Authorize(AuthenticationSchemes = AspNet.Security.OAuth.Validation.OAuthValidationDefaults.AuthenticationScheme, Policy = "user-read-email")]
        [HttpGet("email")]
        public async Task<IActionResult> GetEmail() {
            return Ok("Email Get Request was successful but this endpoint is not yet implemented");
        }

        [RateLimit]
        [Authorize(AuthenticationSchemes = AspNet.Security.OAuth.Validation.OAuthValidationDefaults.AuthenticationScheme, Policy = "user-modify-birthdate")]
        [HttpPut("birthdate")]
        public IActionResult ChangeBirthdate(string birthdate) {
            return Ok("Birthdate Put successful but this endpoint is not yet implemented");
        }

        [RateLimit]
        [Authorize(AuthenticationSchemes = AspNet.Security.OAuth.Validation.OAuthValidationDefaults.AuthenticationScheme, Policy = "user-modify-email")]
        [HttpPut("email")]
        public async Task<IActionResult> ChangeEmail(string email) {
            return Ok("Email Put request received, but function is not yet implemented");
        }

        // Dynamic Scope Methods - Authenticated methods that return additional information the more scopes are supplied
        [Authorize(AuthenticationSchemes = AspNet.Security.OAuth.Validation.OAuthValidationDefaults.AuthenticationScheme)]
        [HttpGet("me")]
        public async Task<IActionResult> Me() {
            return Ok("User Profile Get request received, but function is not yet implemented");
        }
    }
}
