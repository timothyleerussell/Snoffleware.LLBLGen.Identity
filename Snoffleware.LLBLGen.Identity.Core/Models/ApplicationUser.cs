using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace Snoffleware.LLBLGen.Identity.Core.Models
{
    public class ApplicationUser : IdentityUser
    {
        public ApplicationUser()
        { 
        }
        
        //set some defaults so that things work out of the box 
        //you should change these for your application
        public string AuthenticatorKey { get; set; }
        public string LoginProvider { get; set; } = "Snoffleware.LLBLGen.Identity.LoginProvider";
        public string LoginProviderDisplayName { get; set; } = "Snoffleware LLBLGen Identity Login Provider";
        public string LoginProviderKey { get; set; } = "Snoffleware.LLBLGen.Identity.LoginProviderKey";
        public string LoginRecoveryTokenKey { get; set; } = "Snoffleware.LLBLGen.Identity.LoginRecoveryTokenKey";
        public string AuthenticatorKeyTokenName { get; set; } = "Snoffleware.LLBLGen.Identity.AuthenticatorKeyToken";

        //inherited members
        //public string Id { get; set; }
        //public string UserName { get; set; }        
        //public string NormalizedUserName { get; set; }
        //public string Email { get; set; }
        //public string NormalizedEmail { get; set; }
        //public bool EmailConfirmed { get; set; }
        //public string PasswordHash { get; set; }
        //public string SecurityStamp { get; set; }
        //public string ConcurrencyStamp { get; set; }        
        //public string PhoneNumber { get; set; }
        //public bool PhoneNumberConfirmed { get; set; }
        //public bool TwoFactorEnabled { get; set; }
        //public DateTimeOffset? LockoutEnd { get; set; }
        //public bool LockoutEnabled { get; set; }
        //public Int32 AccessFailedCount { get; set; }
    }
}