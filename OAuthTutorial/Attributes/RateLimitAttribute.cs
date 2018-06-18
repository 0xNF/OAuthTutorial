using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using OAuthTutorial.Data;
using OAuthTutorial.Models.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuthTutorial.Attributes {
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class RateLimitAttribute : ActionFilterAttribute {

        /* The cache for all items that will be placed into our rate limit cache */
        private static MemoryCache Cache { get; } = new MemoryCache(new MemoryCacheOptions());
        /* For items that are granted no-rate-limit, place their id in here so that we may avoid multiple database calls. */
        private static MemoryCache WhiteList { get; } = new MemoryCache(new MemoryCacheOptions());

        public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next) {
            ApplicationDbContext db = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
            Claim clientIdClaim = context.HttpContext.User.Claims.FirstOrDefault(x => x.Type == "client_id");
            string token = TokenFromContext(context);

            if (clientIdClaim == null || String.IsNullOrWhiteSpace(clientIdClaim.Value) || String.IsNullOrWhiteSpace(token)) {
                context.Result = new ContentResult { Content = "Failed to find appropriate claims" };
                context.HttpContext.Response.StatusCode = (int)System.Net.HttpStatusCode.BadRequest;
                return;
            }

            /* Closures representing the way to get the rate limit of the relevant item, if necessary.
            * These are lazily executed functions and won't be called unlesss a given id isn't in our cache. */
            async Task<RateLimit> RateLimitFromToken() {
                RateLimit rl = (await db.Tokens.Include(x => x.RateLimit).FirstOrDefaultAsync(x => x.Value == token))?.RateLimit;
                return rl;
            }
            async Task<RateLimit> RateLimitFromClient() {
                RateLimit rl = (await db.ClientApplications.Include(x => x.RateLimit).FirstOrDefaultAsync(x => x.ClientId == clientIdClaim.Value))?.RateLimit;
                return rl;
            }

            bool shortCircuit = await CheckOrApplyRateLimit(token, RateLimitFromToken, "You have issued too many requests. Please check the retry-after headers and try again.", context);
            if (!shortCircuit) {
                /* If the specific token has been rate limited, don't add a count to the Client's overall limit, just exit early. */
                await CheckOrApplyRateLimit(clientIdClaim.Value, RateLimitFromClient, "The application being used has issued too many requests. Please contant the application author.", context);
            }

            await base.OnActionExecutionAsync(context, next);
        }


        private async Task<bool> CheckOrApplyRateLimit(string id, Func<Task<RateLimit>> f, string limitAppliedMessage, ActionExecutingContext context) {
            /* If the item is whitelisted, bail early */
            if (WhiteList.TryGetValue(id, out bool whitelisted)) {
                return true;
            }
            if (!Cache.TryGetValue(id, out LimitCounter counter)) {
                RateLimit rl = await f();
                if (rl == null) {
                    /* Something happened to the client application between the receipt of request and the receipt of rate limit. 
                     * So we'll just short circuit and bail early */
                    return true;
                }
                return InsertLimit(id, rl);
            }
            else {
                return CacheUpdate(context, id, counter, limitAppliedMessage);
            }
        }

        /* Inserts the limit as a LimitCounter struct tied to the given id, and expiring when the Window lapses.
         * The boolean returned indictes whether this item was whitelisted, and therefore if we should
         * short-circuit our computation and return early. 
         */
        private bool InsertLimit(string id, RateLimit limit) {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            /* Nulls in these spots mean this item is whitelisted. Add it to our whitelist. */
            if (limit.Window == null || limit.Limit == null) {
                /* White-listing lasts one hour, so that if whitelisting status changes, server won't require a restart to clear the cache. */
                WhiteList.Set(id, true, new MemoryCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromHours(1)));
                return true;
            }
            else {
                LimitCounter counter = new LimitCounter(now, limit.Window.Value, 1, limit.Limit);
                Cache.Set(id, counter, new MemoryCacheEntryOptions().SetAbsoluteExpiration(limit.Window.Value)); // Passed a null check above, value exists
                return false;
            }
        }

        /* Updates the the cached item with an incremented call-count.
         * Returns whether our incremented count puts us over the limit for the token
         * If so, boolean indicates whether we should short-circuit our conputation and return early.
         */
        private bool CacheUpdate(ActionExecutingContext context, string id, LimitCounter oldCounter, string message) {
            LimitCounter updatedCounter = new LimitCounter(oldCounter.FirstCallTimestamp, oldCounter.Window, oldCounter.CallCount + 1, oldCounter.Limit);

            /* Cache will periodically prune itself, but if we happen to pull one that expired, we'll take care of it. */
            if (oldCounter.FirstCallTimestamp + oldCounter.Window <= DateTimeOffset.UtcNow) {
                Cache.Remove(id);
                return false;
            }

            /* Due to the nature of distributed or off-site storage, limits may be incremented past their theoretical max. 
             * We account for this with a greater than check, rather than a strict equals check */
            if (updatedCounter.CallCount > updatedCounter.Limit) {
                TimeSpan availableAt = (updatedCounter.FirstCallTimestamp + updatedCounter.Window) - DateTimeOffset.UtcNow;

                context.Result = new ContentResult { Content = message };
                context.HttpContext.Response.StatusCode = 429; /* Too Many Requests */
                context.HttpContext.Response.Headers.Add("Retry-After", availableAt.TotalSeconds.ToString());
                return true;
            }
            else {
                Cache.Set(id, updatedCounter, new MemoryCacheEntryOptions().SetAbsoluteExpiration(updatedCounter.FirstCallTimestamp + updatedCounter.Window));
                return false;
            }
        }

        /* Because Tokens are not serialized into themselves, we cannot extract the relevant info 
         * from the claims alone. We must therefore manually grab the Authorization header ourselves.
         */
        private string TokenFromContext(ActionExecutingContext context) {
            string AuthScheme = AspNet.Security.OAuth.Validation.OAuthValidationDefaults.AuthenticationScheme;
            string BearerToken = context.HttpContext.Request.Headers["Authorization"].FirstOrDefault(x => x.StartsWith(AuthScheme));
            string token = "";
            if (String.IsNullOrWhiteSpace(BearerToken)) {
                context.Result = new ContentResult { Content = "Authorization header was missing" };
                context.HttpContext.Response.StatusCode = (int)System.Net.HttpStatusCode.BadRequest;
            }
            else {
                string[] bearerSplit = BearerToken.Split(AuthScheme + " ");
                if (bearerSplit.Length == 0 || String.IsNullOrWhiteSpace(bearerSplit[1])) {
                    context.Result = new ContentResult { Content = "Authorization was incorrectly formatted" };
                    context.HttpContext.Response.StatusCode = (int)System.Net.HttpStatusCode.BadRequest;
                }
                token = bearerSplit[1];
            }
            return token;
        }


    }
}
