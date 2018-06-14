using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OAuthTutorial.Data;
using OAuthTutorial.Models;
using OAuthTutorial.Models.OAuth;
using OAuthTutorial.Models.OAuthClientViewModels;

namespace OAuthTutorial.Controllers
{
    [Authorize]
    public class OAuthClientsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public OAuthClientsController(ApplicationDbContext context, UserManager<ApplicationUser> userManager) {
            _context = context;
            _userManager = userManager;
        }

        // GET: OAuthClients
        public async Task<IActionResult> Index()
        {
            string uid = _userManager.GetUserId(this.User);
            return View(await _context.ClientApplications.Include(x => x.Owner).Where(x => x.Owner.Id == uid).ToListAsync());
        }

        // GET: OAuthClients/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: OAuthClients/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ClientName,ClientDescription")] CreateClientViewModel vm) {
            if (ModelState.IsValid) {
                ApplicationUser owner = await _userManager.GetUserAsync(this.User);
                OAuthClient client = new OAuthClient() {
                    ClientDescription = vm.ClientDescription,
                    ClientName = vm.ClientName,
                    ClientId = Guid.NewGuid().ToString(),
                    ClientSecret = Guid.NewGuid().ToString(),
                    Owner = owner,
                };

                _context.Add(client);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(vm);
        }

        // GET: OAuthClients/Edit/5
        public async Task<IActionResult> Edit(string id) {
            if (String.IsNullOrEmpty(id)) {
                return NotFound();
            }

            string uid = _userManager.GetUserId(this.User);
            var oAuthClient = await _context.ClientApplications.Include(x => x.Owner).Include(x => x.RedirectURIs)
                .SingleOrDefaultAsync(m => m.ClientId == id && m.Owner.Id == uid);
            if (oAuthClient == null) {
                return NotFound();
            }

            EditClientViewModel vm = new EditClientViewModel() {
                ClientName = oAuthClient.ClientName,
                ClientDescription = oAuthClient.ClientDescription,
                ClientId = oAuthClient.ClientId,
                ClientSecret = oAuthClient.ClientSecret,
                RedirectUris = oAuthClient.RedirectURIs.Select(x => x.URI).ToArray()
            };

            return View(vm);
        }

        // POST: OAuthClients/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, [Bind("ClientDescription", "RedirectUris")] EditClientViewModel vm) {
            string uid = _userManager.GetUserId(this.User);
            OAuthClient client = await _context.ClientApplications.Include(x => x.Owner).Include(x => x.RedirectURIs).Where(x => x.ClientId == id && x.Owner.Id == uid).FirstOrDefaultAsync();
            if (client == null) {
                return NotFound();
            }

            if (ModelState.IsValid) {
                try {
                    List<RedirectURI> originalUris = client.RedirectURIs;
                    CheckAndMark(originalUris, vm.RedirectUris);

                    client.ClientDescription = vm.ClientDescription;
                    _context.Update(client);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException) {
                    if (!OAuthClientExists(vm.ClientId)) {
                        return NotFound();
                    }
                    else {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(vm);


            void CheckAndMark(List<RedirectURI> originals, IEnumerable<string> submitted) {
                List<RedirectURI> newList = new List<RedirectURI>();
                foreach (string s in submitted) {
                    if (String.IsNullOrWhiteSpace(s)) {
                        continue;
                    }
                    RedirectURI fromOld = originals.FirstOrDefault(x => x.URI == s);
                    if (fromOld == null) {
                        // this 's' is new.
                        RedirectURI rdi = new RedirectURI() { OAuthClient = client, OAuthClientId = client.ClientId, URI = s };
                        newList.Add(rdi);
                    }
                    else {
                        // this 's' was re-submitted
                        newList.Add(fromOld);
                    }
                }

                // Marking deleted Redirect URIs for Deletion.
                originals.Except(newList).Select(x => _context.Entry(x).State = EntityState.Deleted);

                // Assign the new list back to the client
                client.RedirectURIs = newList;
            }
        }


        // POST: OAuthClients/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id) {

            if (String.IsNullOrEmpty(id)) {
                return NotFound();
            }

            string uid = _userManager.GetUserId(this.User);
            var oAuthClient = await _context.ClientApplications.Include(x => x.Owner)
                .SingleOrDefaultAsync(m => m.ClientId == id && m.Owner.Id == uid);

            if (oAuthClient == null) {
                return NotFound();
            }

            _context.ClientApplications.Remove(oAuthClient);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        // POST: OAuthClients/ResetSecret/
        [HttpPost, ActionName("ResetSecret")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetClientSecret(string id) {

            string uid = _userManager.GetUserId(this.User);
            OAuthClient client = await _context.ClientApplications.Include(x => x.Owner).Include(x => x.RedirectURIs).Where(x => x.ClientId == id && x.Owner.Id == uid).FirstOrDefaultAsync();
            if (client == null) {
                return NotFound();
            }

            try {
                client.ClientSecret = Guid.NewGuid().ToString();
                _context.Update(client);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException) {
                if (!OAuthClientExists(client.ClientId)) {
                    return NotFound();
                }
                else {
                    throw;
                }
            }
            return RedirectToAction(id, "OAuthClients/Edit");
        }


        private bool OAuthClientExists(string id)
        {
            return _context.ClientApplications.Any(e => e.ClientId == id);
        }
    }
}
