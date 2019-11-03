using Microsoft.AspNetCore.Identity;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Snoffleware.LLBLGen.Identity.Core.Models;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

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
            if(defaultRole != null)
            {
                var claims = await _roleManager.GetClaimsAsync(defaultRole);
                
                IList<Claim> claimsToRemove = new List<Claim>();
                foreach(Claim claim in claims)
                {
                    if (claim.Type == claimType && claim.Value == claim1Value)
                    {
                        claimsToRemove.Add(claim);
                    }
                }
                foreach(Claim claim in claimsToRemove)
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
        [TestCleanup]
        public async Task CleanUp()
        {
            var role = await _roleManager.FindByNameAsync(defaultAdminRole);
            if(role != null)
            {
                await _roleManager.DeleteAsync(role);
            }
            role = await _roleManager.FindByNameAsync("newname");
            if(role != null)
            {
                await _roleManager.DeleteAsync(role);
            }
            await base.Cleanup();
        }
    }
}
