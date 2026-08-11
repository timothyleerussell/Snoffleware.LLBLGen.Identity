using Microsoft.AspNetCore.Identity;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Snoffleware.LLBLGen.Identity.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;
//using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Snoffleware.LLBLGen.Identity.Test
{
    [TestClass]
    public class RoleStoreTest : TestBase
    {
        public RoleStoreTest()
        { }

        [TestInitialize]
        public async Task Setup()
        {
            await base.Setup();

            //create the default role
            ApplicationRole role = new ApplicationRole()
            {
                Name = defaultAdminRole
            };
            await _roleManager.CreateAsync(role);
        }
        [TestMethod]
        public async Task FindTheDefaultAdminRole()
        {
            var role = await _roleManager.FindByNameAsync(defaultAdminRole);
            Assert.IsNotNull(role);
        }
        [TestMethod]
        public async Task CreateThreeRolesConfirmExistenceAndDeleteThem()
        {
            ApplicationRole role1 = new ApplicationRole()
            {
                Name = "testRole1"
            };
            ApplicationRole role2 = new ApplicationRole()
            {
                Name = "testRole2"
            };
            ApplicationRole role3 = new ApplicationRole()
            {
                Name = "testRole3"
            };

            IdentityResult result = null;

            result = await _roleManager.CreateAsync(role1);
            Assert.IsTrue(result.Succeeded);
            result = await _roleManager.CreateAsync(role2);
            Assert.IsTrue(result.Succeeded);
            result = await _roleManager.CreateAsync(role3);
            Assert.IsTrue(result.Succeeded);

            var selectRole1 = await _roleManager.FindByNameAsync(role1.Name);
            Assert.IsTrue(selectRole1.Id == role1.Id);
            var selectRole2 = await _roleManager.FindByNameAsync(role2.Name);
            Assert.IsTrue(selectRole2.Id == role2.Id);
            var selectRole3 = await _roleManager.FindByNameAsync(role3.Name);
            Assert.IsTrue(selectRole3.Id == role3.Id);

            var deleteResult = await _roleManager.DeleteAsync(role1);
            Assert.IsTrue(deleteResult.Succeeded);
            deleteResult = await _roleManager.DeleteAsync(role2);
            Assert.IsTrue(deleteResult.Succeeded);
            deleteResult = await _roleManager.DeleteAsync(role3);
            Assert.IsTrue(deleteResult.Succeeded);
        }
        [TestMethod]
        public async Task UpdateARoleName()
        {
            var role = await _roleManager.FindByNameAsync(defaultAdminRole);

            //update
            role.Name = "NewName";
            var setRoleNameResult = await _roleManager.UpdateAsync(role);
            Assert.IsTrue(setRoleNameResult.Succeeded);

            var modifiedRole = await _roleManager.FindByNameAsync("newname");
            Assert.IsTrue(modifiedRole.NormalizedName == "NEWNAME");

            //set it back
            role.Name = defaultAdminRole;
            setRoleNameResult = await _roleManager.UpdateAsync(role);
            Assert.IsTrue(setRoleNameResult.Succeeded);

            modifiedRole = await _roleManager.FindByNameAsync(defaultAdminRole);
            Assert.IsTrue(modifiedRole.NormalizedName == defaultAdminRole.ToUpperInvariant());
        }
        [TestMethod]
        public async Task AddRoleClaim()
        {
            var defaultRole = await _roleManager.FindByNameAsync(defaultAdminRole);
            if (defaultRole != null)
            {
                Claim claim = new Claim(claimType, claim1Value);
                var result = await _roleManager.AddClaimAsync(defaultRole, claim);
                Assert.IsTrue(result.Succeeded);
            }
        }
        [TestMethod]
        public async Task GetClaimsAndRemoveDefaultRoleClaim()
        {
            var defaultRole = await _roleManager.FindByNameAsync(defaultAdminRole);
            if (defaultRole != null)
            {
                var claims = await _roleManager.GetClaimsAsync(defaultRole);

                IList<Claim> claimsToRemove = new List<Claim>();
                foreach (Claim claim in claims)
                {
                    if (claim.Type == claimType && claim.Value == claim1Value)
                    {
                        claimsToRemove.Add(claim);
                    }
                }
                foreach (Claim claim in claimsToRemove)
                {
                    var result = await _roleManager.RemoveClaimAsync(defaultRole, claim);
                    Assert.IsTrue(result.Succeeded);
                }
            }
        }
        [TestMethod]
        public async Task GetAllRolesUsingIQueryable()
        {
            //create 4 Roles
            ApplicationRole role1 = new ApplicationRole()
            {
                Name = "azaza1",
            };
            var result1 = await _roleManager.CreateAsync(role1);
            Assert.IsTrue(result1.Succeeded);
            ApplicationRole role2 = new ApplicationRole()
            {
                Name = "azaza2",
            };
            var result2 = await _roleManager.CreateAsync(role2);
            Assert.IsTrue(result2.Succeeded);
            ApplicationRole role3 = new ApplicationRole()
            {
                Name = "azaza3",
            };
            var result3 = await _roleManager.CreateAsync(role3);
            Assert.IsTrue(result3.Succeeded);
            ApplicationRole role4 = new ApplicationRole()
            {
                Name = "azaza4",
            };
            var result4 = await _roleManager.CreateAsync(role4);
            Assert.IsTrue(result4.Succeeded);

            var roles = _roleManager.Roles;
            Assert.IsInstanceOfType(roles, typeof(IQueryable<ApplicationRole>));
            Assert.IsNotNull(roles);

            Assert.IsTrue(roles.Where(x => x.Name == "azaza1").Count() == 1);
            Assert.IsTrue(roles.Where(x => x.Name == "azaza2").Count() == 1);
            Assert.IsTrue(roles.Where(x => x.Name == "azaza3").Count() == 1);
            Assert.IsTrue(roles.Where(x => x.Name == "azaza4").Count() == 1);

            Assert.IsTrue(roles.Where(x => x.NormalizedName == "AZAZA1").Count() == 1);
            Assert.IsTrue(roles.Where(x => x.Name.Contains("azaza")).Count() == 4);

            var role = await _roleManager.FindByNameAsync("azaza1");
            if (role != null)
            {
                await _roleManager.DeleteAsync(role);
            }
            role = await _roleManager.FindByNameAsync("azaza2");
            if (role != null)
            {
                await _roleManager.DeleteAsync(role);
            }
            role = await _roleManager.FindByNameAsync("azaza3");
            if (role != null)
            {
                await _roleManager.DeleteAsync(role);
            }
            role = await _roleManager.FindByNameAsync("azaza4");
            if (role != null)
            {
                await _roleManager.DeleteAsync(role);
            }

            //refetch the roles to look for the deleted roles
            roles = _roleManager.Roles.Where(x => x.Name.Contains("azaza"));

            Assert.IsTrue(roles.Where(x => x.Name.Contains("azaza")).Count() == 0);
        }




        [TestMethod]
        public async Task CreateAndDeleteRole()
        {
            var roleName = "RandomRole100";
            var result = await _roleManager.CreateAsync(new ApplicationRole(roleName));
            Assert.IsTrue(result.Succeeded);

            var role = await _roleManager.FindByNameAsync(roleName);
            var deleted = await _roleManager.DeleteAsync(role);
            Assert.IsTrue(deleted.Succeeded);
        }

        [TestMethod]
        public async Task CreateRoleAndRoleClaims()
        {
            var roleName = "RandomRole100";
            var result = await _roleManager.CreateAsync(new ApplicationRole(roleName));
            Assert.IsTrue(result.Succeeded);

            var role = await _roleManager.FindByNameAsync(roleName);

            var permission1 = "ReportView";
            var permission2 = "ReportExport";
            var permission3 = "ReportEdit";

            if(role != null)
            {
                await _roleManager.AddClaimAsync(role, new Claim("Permission", permission1));
                await _roleManager.AddClaimAsync(role, new Claim("Permission", permission2));
                await _roleManager.AddClaimAsync(role, new Claim("Permission", permission3));
            }

            var claims = await _roleManager.GetClaimsAsync(role);

            var claim1 = claims.Where(x => x.Type == "Permission" && x.Value == permission1).FirstOrDefault();
            var claim2 = claims.Where(x => x.Type == "Permission" && x.Value == permission2).FirstOrDefault();
            var claim3 = claims.Where(x => x.Type == "Permission" && x.Value == permission3).FirstOrDefault();

            Assert.IsTrue(claim1.Type == "Permission" && claim1.Value == permission1);
            Assert.IsTrue(claim2.Type == "Permission" && claim2.Value == permission2);
            Assert.IsTrue(claim3.Type == "Permission" && claim3.Value == permission3);

            var deleted = await _roleManager.DeleteAsync(role);
            Assert.IsTrue(deleted.Succeeded);
        }

        [TestMethod]
        public async Task CreateUserWithRoleAndRoleClaims()
        {
            //create user
            var suffix = Guid.NewGuid().ToString("N").Substring(0, 8);
            var userName = "UserWithRole42_" + suffix;
            var password = "TestPassword123!";
            var email = $"Blackhole+UserWithRole42_{suffix}@acompanythatmakeseverything.com";
            var user = new ApplicationUser
            {
                UserName = userName,
                Email = email
            };

            var createResult = await _userManager.CreateAsync(user, password);
            Assert.IsTrue(createResult.Succeeded);

            var roleName = "Role42_" + suffix;
            var result = await _roleManager.CreateAsync(new ApplicationRole(roleName));
            Assert.IsTrue(result.Succeeded);

            var permissions = new List<string> { "Permission1", "Permission2", "Permission3" };
            foreach (var permission in permissions)
            {
                await _roleManager.AddClaimAsync(await _roleManager.FindByNameAsync(roleName), new Claim("Permission", permission));
            }

            var role = await _roleManager.FindByNameAsync(roleName);
            var claims = await _roleManager.GetClaimsAsync(role);
            Assert.AreEqual(permissions.Count, claims.Count());
            foreach (var permission in permissions)
            {
                Assert.IsTrue(claims.Any(x => x.Type == "Permission" && x.Value == permission));
            }

            await _userManager.AddToRoleAsync(user, roleName);

            Assert.IsTrue(await _userManager.IsInRoleAsync(user, roleName));


            //doesn't work -
            //    Test method Snoffleware.LLBLGen.Identity.Test.RoleStoreTest.CreateUserWithRoleAndRoleClaims threw exception: 
            //SD.LLBLGen.Pro.ORMSupportClasses.ORMQueryExecutionException: An exception was caught during the execution of a retrieval query: The connection does not support MultipleActiveResultSets..Check InnerException, QueryExecuted and Parameters of this exception to examine the cause of this exception. --->System.InvalidOperationException: The connection does not support MultipleActiveResultSets.

            //await _userManager.RemoveFromRoleAsync(user, roleName);
            //Assert.IsFalse(await _userManager.IsInRoleAsync(user, roleName));













            //this fails due to multipleresultsets, what are the implications of this?

            //await _userManager.RemoveFromRoleAsync(user, roleName);
            //Assert.IsFalse(await _userManager.IsInRoleAsync(user, roleName));


            ////Test method Snoffleware.LLBLGen.Identity.Test.RoleStoreTest.CreateUserWithRoleAndRoleClaims threw exception:
            ////SD.LLBLGen.Pro.ORMSupportClasses.ORMQueryExecutionException: An exception was caught during the execution of a retrieval query: The connection does not support MultipleActiveResultSets..Check InnerException, QueryExecuted and Parameters of this exception to examine the cause of this exception. --->System.InvalidOperationException: The connection does not support MultipleActiveResultSets.


            //await _userManager.RemoveFromRoleAsync(user, roleName);

            ////Assert.IsFalse(await _userManager.IsInRoleAsync(user, roleName));

            //var claimsToDelete = await _roleManager.GetClaimsAsync(role);

            //foreach (var claim in claimsToDelete)
            //{
            //    await _roleManager.RemoveClaimAsync(role, claim);
            //}

            ////var claimsResult = await _roleManager.GetClaimsAsync(role);
            ////Assert.AreEqual(claimsResult.Count, 0);

            //var deleted = await _roleManager.DeleteAsync(role);
            //Assert.IsTrue(deleted.Succeeded);

            //var userDelete = await _userManager.DeleteAsync(user);
            //Assert.IsTrue(userDelete.Succeeded);
        }

        [TestCleanup]
        public async Task CleanUp()
        {
            var role = await _roleManager.FindByNameAsync(defaultAdminRole);
            if (role != null)
            {
                await _roleManager.DeleteAsync(role);
            }
            role = await _roleManager.FindByNameAsync("newname");
            if (role != null)
            {
                await _roleManager.DeleteAsync(role);
            }
            await base.Cleanup();
        }
    }
}
