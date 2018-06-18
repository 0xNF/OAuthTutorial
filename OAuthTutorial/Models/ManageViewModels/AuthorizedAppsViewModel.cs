using OAuthTutorial.Models.OAuth;
using System.Collections.Generic;

namespace OAuthTutorial.Models.ManageViewModels {
    public class AuthorizedAppsViewModel {
        public IList<OAuthClient> AuthorizedApps { get; set; }
    }
}
