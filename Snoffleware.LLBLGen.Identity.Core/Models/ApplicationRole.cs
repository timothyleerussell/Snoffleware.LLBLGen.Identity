using Microsoft.AspNetCore.Identity;

namespace Snoffleware.LLBLGen.Identity.Core.Models
{
    public class ApplicationRole : IdentityRole
    {
        public ApplicationRole() { }

        public ApplicationRole(string name)
        {
            Name = name;
            NormalizedName = name.ToUpperInvariant();
        }

        public override string ToString()
        {
            return Name;
        }

        //inherited members
        //public string Id { get; set; }
        //public string Name { get; set; }
        //public string NormalizedName { get; set; }
        //public string ConcurrencyStamp { get; set; }
    }
}
