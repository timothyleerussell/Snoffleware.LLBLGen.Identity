using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SD.LLBLGen.Pro.ORMSupportClasses;
using SD.LLBLGen.Pro.DQE.SqlServer;
using System.Diagnostics;
using Snoffleware.LLBLGen.Identity.Core.Models;
using Snoffleware.LLBLGen.Identity.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity.UI.Services;
using Snoffleware.LLBLGen.Identity.WebTest.Services;

namespace Snoffleware.LLBLGen.Identity.WebTest
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }       

        public void ConfigureServices(IServiceCollection services)
        {
            //we're not using EF, LLBLGen connection string is set in Configure()
            //
            //services.AddDbContext<ApplicationDbContext>(options =>
            //    options.UseSqlServer(
            //        Configuration.GetConnectionString("DefaultConnection")));
            // we're going to use AddIdentityCore because it sounds more Core-y.
            //services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
            //    .AddEntityFrameworkStores<ApplicationDbContext>();

            IdentityBuilder builder = services.AddIdentityCore<ApplicationUser>()
                .AddUserStore<UserStore>()
                .AddRoles<ApplicationRole>()
                .AddRoleStore<RoleStore>()
                //note that we scaffolded the DefaultUI so that we can specify our SignInManager and UserManager with the correct generic type
                //maybe we need to disable the defaultUI here...?  Unsure, can't find anything referencing this, except this on SO but asks more questions than it answers
                //https://stackoverflow.com/questions/50615597/net-core-identity-as-ui-canceling-register
                //it appears: yes, this needs to be removed after you have scaffolded the pages
                //take that back...it appears we do need it...because it registers the controller logic presumably
                //TODO Microsoft: should be able to specify custom user/role types to the scaffolder, the UI of that tool suggests it's possible but has some validation issues
                //that make it not possible in my attempts. Then it wouldn't be necessary to physically scaffold the ui, just the provide the updated custom user/role types in the 
                //ViewImports. Maybe I'm just missing the "right" way to do this.
                .AddDefaultUI()
                .AddSignInManager<SignInManager<ApplicationUser>>()
                .AddUserManager<UserManager<ApplicationUser>>()
                .AddRoleManager<RoleManager<ApplicationRole>>()                
                .AddDefaultTokenProviders();


            #region adding services manually, which are necessary?
            //TL;DR -> not sure which of these we need to register manually -- research
            //
            //Alice brought me here and there still might be some of these that need to be registered with DI
            //but Microsoft has a number of different methods - AddDefaultIdentity, AddIdentity, AddIdentityCore now, etc...
            //not entirely clear what they do without looking at the source. One doesn't have roles...etc.
            //trying to go "full core" so I'm using AddIdentityCore
            //
            //*** AddIdentityCore() registers this ***
            //services.AddScoped<IUserValidator<ApplicationUser>, UserValidator<ApplicationUser>>();
            
            //*** AddIdentityCore() registers this ***
            //services.AddScoped<IPasswordValidator<ApplicationUser>, PasswordValidator<ApplicationUser>>();

            //*** AddIdentityCore() registers this ***
            //services.AddScoped<IPasswordHasher<ApplicationUser>, PasswordHasher<ApplicationUser>>();

            //*** AddIdentityCore() registers this ***
            //services.AddScoped<ILookupNormalizer, UpperInvariantLookupNormalizer>();

            //*** AddIdentityCore() registers this ***
            //services.AddScoped<IdentityErrorDescriber>();

            //*** AddIdentityCore() registers this ***
            //services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>, UserClaimsPrincipalFactory<ApplicationUser>>();

            //*** NOT registered by AddIdentityCore() ***
            //we need these for a successful compilation since we implemented all the "store" interface points
            //not sure the recommended type of registration - i.e. scoped/transient/singleton
            services.AddScoped<ISecurityStampValidator, SecurityStampValidator<ApplicationUser>>();
            services.AddScoped<ITwoFactorSecurityStampValidator, TwoFactorSecurityStampValidator<ApplicationUser>>();

            //*** NOT registered by AddIdentityCore() ***
            services.AddScoped<IRoleValidator<ApplicationRole>, RoleValidator<ApplicationRole>>();

            ////we can instead add these three items above in the AddIdentityCore() fluent call
            //services.AddScoped<UserManager<ApplicationUser>>();
            //services.AddScoped<SignInManager<ApplicationUser>>();
            //services.AddScoped<RoleManager<ApplicationRole>>();

            //we also need an EmailSender -- stubbed it out -- it writes to Debug console currently
            //find it in the WebTest project in the services directory
            //some examples suggested to have this be scoped but I think it should be transient?
            //services.AddScoped<IEmailSender, EmailSender>();
            services.AddTransient<IEmailSender, EmailSender>();
            services.Configure<AuthMessageSenderOptions>(Configuration);

            //apparently need ISystemClock registered for the SecurityStampValidator, not listed in any docs I can find? -- failing without it --
            //https://github.com/aspnet/AspNetCore/issues/4428
            //suggests services.AddScoped<ISystemClock, SystemClock>();
            //but should be a singleton?
            services.AddSingleton<ISystemClock, SystemClock>();
            #endregion  

            //these "Schemes" appear to be the switches to control what cookies gets written where and when
            //but scarse documentation
            //
            //when you override the UserStore and RoleStore, the Identity system looks at what you have overridden,
            //not sure how to turn off features that we've defined in the Stores so that it can be a general purpose provider.
            //
            //there are some interconnections, not sure how some of these things are related and what they do internally
            //but you have to define the cookies for all the situations if you have overridden all of the UserStore/RoleStore methods
            //or I'm doing it wrong. Quite possible!
            //
            //would be nice to have better docs
            //
            //Don't know what the best practices are for these cookies
            //currently they are cloned, except for the name.
            //The minimum to get the example to compile for some simple front-end tests...
            
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
                //options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
                options.DefaultChallengeScheme = IdentityConstants.TwoFactorUserIdScheme;
                options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
                options.DefaultSignOutScheme = IdentityConstants.ApplicationScheme;
            })
            .AddCookie(IdentityConstants.ApplicationScheme,
                options =>
                {
                    options.Cookie.Name = "Snoffleware.LLBLGen.Identity.Cookie";
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SameSite = SameSiteMode.Strict;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

                    options.ExpireTimeSpan = TimeSpan.FromHours(0.25);
                    options.SlidingExpiration = true;
                    options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;

                    options.LoginPath = $"/Identity/Account/Login";
                    options.LogoutPath = $"/Identity/Account/Logout";
                    options.AccessDeniedPath = $"/Identity/Account/AccessDenied";
                })
            .AddCookie(IdentityConstants.ExternalScheme,
                options =>
                {
                    options.Cookie.Name = "Snoffleware.LLBLGen.Identity.External.Cookie";
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SameSite = SameSiteMode.Strict;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

                    options.ExpireTimeSpan = TimeSpan.FromHours(0.25);
                    options.SlidingExpiration = true;
                    options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;

                    options.LoginPath = $"/Identity/Account/Login";
                    options.LogoutPath = $"/Identity/Account/Logout";
                    options.AccessDeniedPath = $"/Identity/Account/AccessDenied";
                })
             .AddCookie(IdentityConstants.TwoFactorRememberMeScheme,
                options =>
                {
                    options.Cookie.Name = "Snoffleware.LLBLGen.Identity.TwoFactorRememberMe.Cookie";
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SameSite = SameSiteMode.Strict;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

                    options.ExpireTimeSpan = TimeSpan.FromHours(0.25);
                    options.SlidingExpiration = true;
                    options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;

                    options.LoginPath = $"/Identity/Account/Login";
                    options.LogoutPath = $"/Identity/Account/Logout";
                    options.AccessDeniedPath = $"/Identity/Account/AccessDenied";
                })
            .AddCookie(IdentityConstants.TwoFactorUserIdScheme,
                options =>
                {
                    options.Cookie.Name = "Snoffleware.LLBLGen.Identity.TwoFactorUserId.Cookie";
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SameSite = SameSiteMode.Strict;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

                    options.ExpireTimeSpan = TimeSpan.FromHours(0.25);
                    options.SlidingExpiration = true;
                    options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;

                    options.LoginPath = $"/Identity/Account/Login";
                    options.LogoutPath = $"/Identity/Account/Logout";
                    options.AccessDeniedPath = $"/Identity/Account/AccessDenied";                    
                });

            services.Configure<IdentityOptions>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 10;
                options.Password.RequiredLength = 8;
                options.Password.RequireDigit = true;
                options.Password.RequiredUniqueChars = 1;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;
            });

            services.Configure<ClaimsIdentityOptions>(options =>
            {
            });

            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddControllersWithViews();
            services.AddRazorPages();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                //EF database error page provider, not using
                //app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });

            //LLBLGen
            //config hard-coded
            //RuntimeConfiguration.AddConnectionString("ConnectionString.SQL Server (SqlClient)", "data source=YOURCOMPUTER\\SQLINSTANCE;initial catalog=Snoffleware-LLBLGen-Identity-Dev;integrated security=SSPI;persist security info=False");

            //but we don't want to do this so we will pull from the new Secret Manager store locally
            //*** add a key to the secrets store for _each_ project that needs to access data through LLBLGen ***
            //*** "ConnectionString.SQL Server (SqlClient)" plus your connection string ***

            //careful, secrets holds on to a double-wack-slash so it will double and not work when you pull it forward.
            //-- i.e. don't escape the connection string when you pass it to the Secret Manager via the command line, see:
            //https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets/

            //example powershell command in README...

            string connectionStringKey = "ConnectionString.SQL Server (SqlClient)";
            string connectionStringValue = Configuration[connectionStringKey];
            RuntimeConfiguration.AddConnectionString(connectionStringKey, connectionStringValue);

            RuntimeConfiguration.ConfigureDQE<SQLServerDQEConfiguration>(
                                            c => c.SetTraceLevel(TraceLevel.Verbose)
                                                    //.AddCatalogNameOverwrite("Snoffleware-LLBLGen-Identity-Dev", "")  //may be necessary on azure
                                                    .AddDbProviderFactory(typeof(System.Data.SqlClient.SqlClientFactory))
                                                    .SetDefaultCompatibilityLevel(SqlServerCompatibilityLevel.SqlServer2012));

        }
    }
}
