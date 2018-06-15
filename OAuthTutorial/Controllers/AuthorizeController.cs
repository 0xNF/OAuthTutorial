using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OAuthTutorial.Data;
using OAuthTutorial.Models;

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
            return Ok();
        }

        [HttpPost("deny")]
        public async Task<IActionResult> Deny() {
            return LocalRedirect("/");
        }

        [HttpPost("accept")]
        public async Task<IActionResult> Accept() {
            // TODO this will be a big method, we'll address it further down below.
            return Ok();
        }

    }
}
