using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Snoffleware.LLBLGen.Identity.Core.Models
{
    public class ApplicationUserRole : IdentityUserRole<string>
    {
        //TODO: these navigation properties are from the docs relating to entity framework - which we aren't using
        //should these be some sort of llblgen relation?
        public virtual ApplicationUser User { get; set; }
        public virtual ApplicationRole Role { get; set; }
    }
}
