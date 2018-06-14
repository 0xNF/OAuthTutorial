using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OAuthTutorial.Data;
using OAuthTutorial.Models.OAuth;

namespace OAuthTutorial.Controllers
{
    [Authorize]
    public class OAuthClientsController : Controller
    {
        private readonly ApplicationDbContext _context;

        public OAuthClientsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: OAuthClients
        public async Task<IActionResult> Index()
        {
            return View(await _context.ClientApplications.ToListAsync());
        }

        // GET: OAuthClients/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var oAuthClient = await _context.ClientApplications
                .SingleOrDefaultAsync(m => m.ClientId == id);
            if (oAuthClient == null)
            {
                return NotFound();
            }

            return View(oAuthClient);
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
        public async Task<IActionResult> Create([Bind("ClientId,ClientSecret,ClientName,ClientDescription")] OAuthClient oAuthClient)
        {
            if (ModelState.IsValid)
            {
                _context.Add(oAuthClient);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(oAuthClient);
        }

        // GET: OAuthClients/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var oAuthClient = await _context.ClientApplications.SingleOrDefaultAsync(m => m.ClientId == id);
            if (oAuthClient == null)
            {
                return NotFound();
            }
            return View(oAuthClient);
        }

        // POST: OAuthClients/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, [Bind("ClientId,ClientSecret,ClientName,ClientDescription")] OAuthClient oAuthClient)
        {
            if (id != oAuthClient.ClientId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(oAuthClient);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!OAuthClientExists(oAuthClient.ClientId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(oAuthClient);
        }

        // GET: OAuthClients/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var oAuthClient = await _context.ClientApplications
                .SingleOrDefaultAsync(m => m.ClientId == id);
            if (oAuthClient == null)
            {
                return NotFound();
            }

            return View(oAuthClient);
        }

        // POST: OAuthClients/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var oAuthClient = await _context.ClientApplications.SingleOrDefaultAsync(m => m.ClientId == id);
            _context.ClientApplications.Remove(oAuthClient);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool OAuthClientExists(string id)
        {
            return _context.ClientApplications.Any(e => e.ClientId == id);
        }
    }
}
