using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Snoffleware.LLBLGen.Identity.Core.Models;
using Snoffleware.LLBLGen.Identity.WebTest.Models;

[assembly: HostingStartup(typeof(Snoffleware.LLBLGen.Identity.WebTest.Areas.Identity.IdentityHostingStartup))]
namespace Snoffleware.LLBLGen.Identity.WebTest.Areas.Identity
{
    public class IdentityHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices((context, services) => {
            });
        }
    }
}

//original scaffolded MS 3.0 version -- we're handling this stuff in startup.cs instead, I think, via the AddIdentityCore() method and loading LLBLGen manually.

//using System;
//using Microsoft.AspNetCore.Hosting;
//using Microsoft.AspNetCore.Identity;
//using Microsoft.AspNetCore.Identity.UI;
//using Microsoft.EntityFrameworkCore;
//using Microsoft.Extensions.Configuration;
//using Microsoft.Extensions.DependencyInjection;
//using Snoffleware.LLBLGen.Identity.Core.Models;
//using Snoffleware.LLBLGen.Identity.WebTest.Models;

//[assembly: HostingStartup(typeof(Snoffleware.LLBLGen.Identity.WebTest.Areas.Identity.IdentityHostingStartup))]
//namespace Snoffleware.LLBLGen.Identity.WebTest.Areas.Identity
//{
//    public class IdentityHostingStartup : IHostingStartup
//    {
//        public void Configure(IWebHostBuilder builder)
//        {
//            //don't know that we need to do anything here in this net core 3 identity scaffolded code...
//            //but maybe LLBLGen should be setup here?

//            //builder.ConfigureServices((context, services) => {
//            //    services.AddDbContext<SnofflewareLLBLGenIdentityWebTestContext>(options =>
//            //        options.UseSqlServer(
//            //            context.Configuration.GetConnectionString("SnofflewareLLBLGenIdentityWebTestContextConnection")));

//            //    services.AddDefaultIdentity<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true)
//            //        .AddEntityFrameworkStores<SnofflewareLLBLGenIdentityWebTestContext>();
//            //});
//        }
//    }
//}