using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace OAuthTutorial.Policies {
    public class AuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider {
        private readonly IConfiguration _configuration;

        private readonly AuthorizationOptions _options;

        public AuthorizationPolicyProvider(IOptions<AuthorizationOptions> options, IConfiguration configuration) : base(options) {
            _configuration = configuration;
            _options = options.Value;
        }

        public override async Task<AuthorizationPolicy> GetPolicyAsync(string policyName) {
            // Check static policies first
            var policy = await base.GetPolicyAsync(policyName);

            if (policy == null) {
                policy = new AuthorizationPolicyBuilder()
                    .AddRequirements(new HasScopeRequirement(policyName, "LOCAL AUTHORITY"))
                    .Build();
                _options.AddPolicy(policyName, policy);
            }
            return policy;
        }

    }
}
