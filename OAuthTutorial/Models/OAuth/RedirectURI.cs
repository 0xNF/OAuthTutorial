using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OAuthTutorial.Models.OAuth {
    public class RedirectURI {

        /*  These are the Foreign Key anchors that, combined with the OAuthClient.RedirectURIs field, lets EntityFramework know that this is a (1 : Many) mapping */
        public string OAuthClientId { get; set; }
        public OAuthClient OAuthClient { get; set; }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string URI { get; set; }

    }
}
