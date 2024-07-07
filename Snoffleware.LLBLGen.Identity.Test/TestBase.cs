//using Microsoft.AspNetCore.Builder;
//using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SD.LLBLGen.Pro.DQE.SqlServer;
using SD.LLBLGen.Pro.ORMSupportClasses;
using Snoffleware.LLBLGen.Identity.Core;
using Snoffleware.LLBLGen.Identity.Core.Models;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Snoffleware.LLBLGen.Identity.Test
{
    public abstract class TestBase
    {
        protected UserManager<ApplicationUser> _userManager;
        protected RoleManager<ApplicationRole> _roleManager;

        protected string defaultUserName = "Bob12345";
        protected string defaultUserEmail = "Bob12345@Bob12345.com";
        protected string defaultPassword = "123456Bc@abcde";

        protected string defaultAdminRole = "testadmin";

        protected string claimType = "master-of-this-universe";
        protected string claim1Value = "by-the-power-of-grayskull";
        protected string claim2Value = "skeletor-must-possess-all";

        protected string user1Name = "Dob12345";
        protected string user1Email = "Dob12345@Dob12345.com";
        protected string user2Name = "Fob12345";
        protected string user2Email = "Fob12345@Fob12345.com";

        protected string loginProvider = "Snoffleware.LLBLGen.Identity.Provider";
        protected string loginProviderDisplayName = "Snoffleware Studios LLC Identity Core with LLBLGen";
        protected string loginProviderKey = "Snoffleware.LLBLGen.Identity.ProviderKey";
        protected string loginRecoveryTokenKey = "Snoffleware.LLBLGen.Identity.RecoveryCodes";

        protected string authenticatorKeyTokenName = "Snoffleware.LLBLGen.Identity.AuthenticatorKey";
        protected string authenticatorKeyTokenValue = "Snoffleware.LLBLGen.Identity.AuthenticatorValue";
        protected string securityCookieName = "Snoffleware.LLBLGen.Identity.Cookie";

        public static void UserStoreTest()
        { }

        [ClassInitialize]
        public async Task Setup()
        {
            var services = new ServiceCollection();

            IdentityBuilder builder = services.AddIdentityCore<ApplicationUser>();
            builder.AddUserStore<UserStore>();
            builder.AddRoles<ApplicationRole>();
            builder.AddRoleStore<RoleStore>();

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

            //services.Configure<CookiePolicyOptions>(options =>
            //{
            //    options.CheckConsentNeeded = context => true;
            //    options.MinimumSameSitePolicy = SameSiteMode.None;
            //});

            //services.AddMvcCore();

            _userManager = services.BuildServiceProvider().GetService<UserManager<ApplicationUser>>();
            _roleManager = services.BuildServiceProvider().GetService<RoleManager<ApplicationRole>>();


            //LLBLGen
            //config hard-coded
            //if you want to run it without setting up the user secrets, you can just add your connection string manually
            //and comment out the 4 lines below that add the connection string using secrets
            //RuntimeConfiguration.AddConnectionString("ConnectionString.SQL Server (SqlClient)", "data source=YOURCOMPUTER\\SQLINSTANCE;initial catalog=Snoffleware-LLBLGen-Identity-Dev;integrated security=SSPI;persist security info=False");

            ////but we don't want to do this so we will pull from the new Secret Manager store locally
            ////*** add a key to the secrets store for _each_ project that needs to access data through LLBLGen ***
            ////*** "ConnectionString.SQL Server (SqlClient)" plus your connection string ***

            ////careful, secrets holds on to a double-wack-slash so it will double and not work when you pull it forward.
            ////-- i.e. don't escape the connection string when you pass it to the Secret Manager via the command line, see:
            ////https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets/
            ///
            //string connectionStringKey = "ConnectionString.SQL Server (SqlClient)";
            //string connectionStringValue = Configuration[connectionStringKey];
            //RuntimeConfiguration.AddConnectionString(connectionStringKey, connectionStringValue);

            //this doesn't work in the test project because we need to manually build the Configuration object for accessing Secret Manager
            string connectionStringKey = "ConnectionString.SQL Server (SqlClient)";

            ConfigurationUtility.GetIConfigurationRoot();
            string connectionStringValue = ConfigurationUtility.GetSecret(connectionStringKey);
            RuntimeConfiguration.AddConnectionString(connectionStringKey, connectionStringValue);
            RuntimeConfiguration.ConfigureDQE<SQLServerDQEConfiguration>(
                                            c => c.SetTraceLevel(TraceLevel.Verbose)
                                                    //.AddCatalogNameOverwrite("Snoffleware-LLBLGen-Identity-Dev", "")  //may be necessary on azure
                                                    .AddDbProviderFactory(typeof(System.Data.SqlClient.SqlClientFactory))
                                                    .SetDefaultCompatibilityLevel(SqlServerCompatibilityLevel.SqlServer2012));
        }

        [ClassCleanup]
        public Task Cleanup()
        {
            return Task.CompletedTask;
        }
    }
}
