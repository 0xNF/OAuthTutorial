using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthTutorial.Models.OAuthClientViewModels {
    public class CreateClientViewModel {
        [Required]
        [MinLength(2)]
        [MaxLength(100)]
        public string ClientName { get; set; }

        [Required]
        [MinLength(1)]
        [MaxLength(500)]
        public string ClientDescription { get; set; }
    }
}
