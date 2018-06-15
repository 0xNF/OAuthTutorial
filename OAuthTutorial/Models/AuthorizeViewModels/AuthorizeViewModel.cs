using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthTutorial.Models.AuthorizeViewModels
{
    public class AuthorizeViewModel {

        public string ClientName { get; internal set; }

        public string ClientId { get; internal set; }

        public string ClientDescription { get; internal set; }

        public string ResponseType { get; internal set; }

        public string RedirectUri { get; internal set; }

        public string[] Scopes { get; internal set; } = new string[0];

        public string State { get; internal set; }

    }
}
