using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace PruebaUserIdentity.API.Models
{
    public class User : IdentityUser
    {
        public string NombreColombiano { get; set; }      

        public bool Activo { get; set; }
    }
}
