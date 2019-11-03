using Microsoft.AspNetCore.Identity;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Snoffleware.LLBLGen.Identity.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Snoffleware.LLBLGen.Identity.Test
{
    [TestClass]
    public class UserStoreTest : TestBase
    {
        public UserStoreTest()
        { }

        [TestInitialize]
        public async Task Setup()
        {
            await base.Setup();

            //clean up default test user if it exists
            var deleteUser = await _userManager.FindByNameAsync(defaultUserName);
            if (deleteUser != null)
            {
                await _userManager.DeleteAsync(deleteUser);
            }

            //start out with a default user
            ApplicationUser user = new ApplicationUser()
            {
                UserName = defaultUserName,
                Email = defaultUserEmail
            };

            var result = await _userManager.CreateAsync(user, defaultPassword);
            Assert.IsTrue(result.Succeeded);
        }

        #region IQueryable<ApplicationUser>
        [TestMethod]
        public async Task UserCollectionIQueryableTest()
        {
            //create 4 users
            ApplicationUser user1 = new ApplicationUser()
            {
                UserName = "a1",
                Email = "a1@a1.pi"
            };
            var result1 = await _userManager.CreateAsync(user1, defaultPassword);
            Assert.IsTrue(result1.Succeeded);
            ApplicationUser user2 = new ApplicationUser()
            {
                UserName = "a2",
                Email = "a2@a2.pi"
            };
            var result2 = await _userManager.CreateAsync(user2, defaultPassword);
            Assert.IsTrue(result2.Succeeded);
            ApplicationUser user3 = new ApplicationUser()
            {
                UserName = "a3",
                Email = "a3@a3.vi"
            };
            var result3 = await _userManager.CreateAsync(user3, defaultPassword);
            Assert.IsTrue(result3.Succeeded);
            ApplicationUser user4 = new ApplicationUser()
            {
                UserName = "a4",
                Email = "a4@a4.vi"
            };
            var result4 = await _userManager.CreateAsync(user4, defaultPassword);
            Assert.IsTrue(result4.Succeeded);

            var users = _userManager.Users;
            Assert.IsInstanceOfType(users, typeof(IQueryable<ApplicationUser>));
            Assert.IsNotNull(users);

            ////records inserted
            Assert.IsTrue(users.Where(x => x.Email == "a1@a1.pi").Count() == 1);
            Assert.IsTrue(users.Where(x => x.UserName == "a2").Count() == 1);
            Assert.IsTrue(users.Where(x => x.Email == "a3@a3.vi").Count() == 1);
            Assert.IsTrue(users.Where(x => x.UserName == "a4").Count() == 1);

            Assert.IsTrue(users.Where(x => x.Email.Contains(".pi")).Count() == 2);
            Assert.IsTrue(users.Where(x => x.Email.Contains(".vi")).Count() == 2);

            Assert.IsTrue(users.Where(x => x.UserName.Contains(".pi") || x.UserName.Contains(".vi")).Count() == 0);

            Assert.IsTrue(users.Where(x => x.NormalizedUserName == "A1").Count() == 1);
            Assert.IsTrue(users.Where(x => x.NormalizedEmail == "A1@A1.PI").Count() == 1);

            Assert.IsTrue(users.Where(x => x.EmailConfirmed == false && (x.Email.Contains(".pi") || x.Email.Contains(".vi"))).Count() == 4);
        }
        #endregion

        #region create users
        [TestMethod]
        public async Task CreateAnExistingTestUser()
        {
            //user created during test startup exists - this should fail
            ApplicationUser user = new ApplicationUser()
            {
                UserName = defaultUserName,
                Email = defaultUserEmail
            };
            var result = await _userManager.CreateAsync(user, defaultPassword);
            Assert.IsTrue(!result.Succeeded);
        }

        [TestMethod]
        public async Task CreateAndImmediatelyDeleteAUser()
        {
            //create a new user, select it and delete it
            ApplicationUser user = new ApplicationUser()
            {
                UserName = "NewRandomUser",
                Email = "NewRandomUser@NewRandomUser.com"
            };
            var createResult = await _userManager.CreateAsync(user, defaultPassword);
            Assert.IsTrue(createResult.Succeeded);

            var selectResult = await _userManager.FindByNameAsync(user.UserName);
            Assert.IsTrue(selectResult.Email == "NewRandomUser@NewRandomUser.com");

            var deleteResult = await _userManager.DeleteAsync(user);
            Assert.IsTrue(deleteResult.Succeeded);

            Assert.IsTrue(createResult.Succeeded && deleteResult.Succeeded);
        }

        [TestMethod]
        public async Task CreateUserFetchByIdAndCheck()
        {
            ApplicationUser user = new ApplicationUser()
            {
                UserName = defaultUserName,
                Email = defaultUserEmail
            };
            var result = await _userManager.CreateAsync(user, defaultPassword);

            if (result.Succeeded)
            {
                var userRefreshed = await _userManager.FindByIdAsync(user.Id);

                if (userRefreshed != null)
                {
                    Assert.IsTrue(userRefreshed.UserName == defaultUserName);
                }
            }
        }
        #endregion

        #region password tests
        [TestMethod]
        public async Task ChangeUserPassword()
        {
            string newPassword = "Mm#%12345abcd";

            //change it
            var user = await _userManager.FindByNameAsync(defaultUserName);
            string passwordHash = user.PasswordHash;
            IdentityResult changePassword = await _userManager.ChangePasswordAsync(user, defaultPassword, newPassword);
            Assert.AreNotEqual(user.PasswordHash, passwordHash);

            //change it back
            user = await _userManager.FindByNameAsync(defaultUserName);
            IdentityResult changePasswordBack = await _userManager.ChangePasswordAsync(user, newPassword, defaultPassword);
            passwordHash = user.PasswordHash;
            Assert.AreEqual(user.PasswordHash, passwordHash);
        }

        [TestMethod]
        public async Task TestReallyLongPassword()
        {
            //using nvarchar(max), allow any size password
            string newPassword = "Mm#%12345abcdadsjkdj32#@JDASJDSJkdjj23oijeirj909043294039u0qjdajahahfd98suaud9990eu902u4094ur90uw0e09u90e98wey7y9y98rehaiojdo" +
                "dskj9u20309hdgfgfhdhhhhhkjoifj@$%^(RAJSDJFjadj009jajlkdjalhhasdl;ji;jaroijejwj09dajksjldjs;lkajddsakjdlkjkasjdlkjaslkjdlkjsdljaslkdjldkddsdjkd" +
                "dskj9u203094dhdhfgdgs5FSRETSSGDFSGGFSFSDFSDGDSFsldkjoifj@$%^(RAJSDJFjadj009jajldhdfgfgdhjldjs;lkajddsakjdlkjkasjdlkjaslkjdlkjsdhhdhfhdkddsdjkd" +
                "dskj9u203094jklajdljasldkjoifj@$%^(RAJSDJFjadj009jajlkdjalhhasdl;ji;jaroijejwj09dajksjlSFJIJ$KJ@KJ%JSKJDLFKSDFJK$J@KJK%JK#%JJRaslkdjldkddsdjkd" +
                "ajew90ajkljd243984094309840380940384308904098349804809480948049830438094830948098043980498340398dsakjdlkjkasjdlkjaslkjdlkjsdljaslkdjldkddsdjkd" +
                "dskAJSDJjjoi4j24j@#$%(^)#)$JSfkj09er093u345jtjskjfkjdfJ#JWE)R@$RJAJDAJE)R@JWEKAJSDPKWEp#@j4rq0rua904jwjadlkjs90230942jjajksldkdjsjjjldkddsdjkd";

            //change it
            var user = await _userManager.FindByNameAsync(defaultUserName);
            string passwordHash = user.PasswordHash;
            IdentityResult changePassword = await _userManager.ChangePasswordAsync(user, defaultPassword, newPassword);
            Assert.AreNotEqual(user.PasswordHash, passwordHash);

            //change it back
            user = await _userManager.FindByNameAsync(defaultUserName);
            IdentityResult changePasswordBack = await _userManager.ChangePasswordAsync(user, newPassword, defaultPassword);
            passwordHash = user.PasswordHash;
            Assert.AreEqual(user.PasswordHash, passwordHash);
        }

        [TestMethod]
        public async Task TestReallyShortPassword()
        {
            string newPassword = "12345"; //password is set to min 8 so anything shorter than that should fail

            //change it
            var user = await _userManager.FindByNameAsync(defaultUserName);
            string passwordHash = user.PasswordHash;
            IdentityResult changePassword = await _userManager.ChangePasswordAsync(user, defaultPassword, newPassword);
            Assert.IsFalse(changePassword.Succeeded);
        }

        [TestMethod]
        public async Task TestPasswordWithoutDigit()
        {
            string newPassword = "aBcDeFgH$"; //password requires digit, should fail

            //change it
            var user = await _userManager.FindByNameAsync(defaultUserName);
            string passwordHash = user.PasswordHash;
            IdentityResult changePassword = await _userManager.ChangePasswordAsync(user, defaultPassword, newPassword);
            Assert.IsFalse(changePassword.Succeeded);
        }

        [TestMethod]
        public async Task TestPasswordWithoutSpecialCharacter()
        {
            string newPassword = "aBcDeFgH1"; //password requires special character, should fail

            //change it
            var user = await _userManager.FindByNameAsync(defaultUserName);
            string passwordHash = user.PasswordHash;
            IdentityResult changePassword = await _userManager.ChangePasswordAsync(user, defaultPassword, newPassword);
            Assert.IsFalse(changePassword.Succeeded);
        }

        [TestMethod]
        public async Task TestPasswordWithoutLowercase()
        {
            string newPassword = "ABCDEFGH1$"; //password requires lowercase, should fail

            //change it
            var user = await _userManager.FindByNameAsync(defaultUserName);
            string passwordHash = user.PasswordHash;
            IdentityResult changePassword = await _userManager.ChangePasswordAsync(user, defaultPassword, newPassword);
            Assert.IsFalse(changePassword.Succeeded);
        }

        [TestMethod]
        public async Task TestPasswordWithoutUppercase()
        {
            string newPassword = "abcdefgh1$"; //password requires uppercase, should fail

            //change it
            var user = await _userManager.FindByNameAsync(defaultUserName);
            string passwordHash = user.PasswordHash;
            IdentityResult changePassword = await _userManager.ChangePasswordAsync(user, defaultPassword, newPassword);
            Assert.IsFalse(changePassword.Succeeded);
        }

        [TestMethod]
        public async Task TestPasswordChangeToCurrentPassword()
        {
            string newPassword = defaultPassword; //password change to current password, should fail (but net core identity allows this)

            //change it
            var user = await _userManager.FindByNameAsync(defaultUserName);
            string passwordHash = user.PasswordHash;
            IdentityResult changePassword = await _userManager.ChangePasswordAsync(user, defaultPassword, newPassword);
            Assert.IsTrue(changePassword.Succeeded);
        }
        #endregion

        #region user/role tests
        [TestMethod]
        public async Task AddDefaultRoleAndCheckIfUserIsInRole()
        {
            ApplicationRole role = new ApplicationRole();
            role.Name = defaultAdminRole;
            await _roleManager.CreateAsync(role);

            var user = await _userManager.FindByNameAsync(defaultUserName);
            await _userManager.AddToRoleAsync(user, defaultAdminRole);

            var roles = await _userManager.GetRolesAsync(user);
            Assert.IsTrue(roles.Contains(defaultAdminRole.ToUpperInvariant()));

            IdentityResult result = await _roleManager.DeleteAsync(role);
            Assert.IsTrue(result.Succeeded);
        }

        [TestMethod]
        public async Task AddUserToRoleThatDoesNotExist()
        {
            //I think this should fail? This role does not exist prior
            var spuriousRole = "supercalifragilisticexpialidocious";
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);
            IdentityResult result = await _userManager.AddToRoleAsync(user, spuriousRole);
            Assert.IsTrue(result.Succeeded);

            var userRoles = await _userManager.GetRolesAsync(user);
            Assert.IsFalse(userRoles.Contains(spuriousRole));
        }
        #endregion

        #region user changes a value
        [TestMethod]
        public async Task UserChangesUserName()
        {
            string newName = "Bobby12345";
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);
            user.UserName = newName;
            IdentityResult result = await _userManager.UpdateAsync(user);
            Assert.IsTrue(result.Succeeded);

            var userRefreshed = await _userManager.FindByEmailAsync(defaultUserEmail);
            Assert.IsTrue(userRefreshed.UserName == newName);
            Assert.IsTrue(userRefreshed.NormalizedUserName == newName.ToUpperInvariant());

            //change it back
            user.UserName = defaultUserName;
            IdentityResult resultChangeUserName = await _userManager.UpdateAsync(user);
            Assert.IsTrue(resultChangeUserName.Succeeded);

            userRefreshed = await _userManager.FindByEmailAsync(defaultUserEmail);
            Assert.IsTrue(userRefreshed.UserName == defaultUserName);
            Assert.IsTrue(userRefreshed.NormalizedUserName == defaultUserName.ToUpperInvariant());
        }

        [TestMethod]
        public async Task UserChangesEmailAddress()
        {
            string newEmail = "updatedemail@newemailaddress.net";
            var user = await _userManager.FindByNameAsync(defaultUserName);
            user.Email = newEmail;
            IdentityResult resultChangeEmail = await _userManager.UpdateAsync(user);
            Assert.IsTrue(resultChangeEmail.Succeeded);

            var userRefreshed = await _userManager.FindByEmailAsync(newEmail);
            Assert.IsTrue(userRefreshed.Email == newEmail);
            Assert.IsTrue(userRefreshed.NormalizedEmail == newEmail.ToUpperInvariant());

            //change it back
            user.Email = defaultUserEmail;
            IdentityResult resultChangeEmailBack = await _userManager.UpdateAsync(user);
            Assert.IsTrue(resultChangeEmailBack.Succeeded);

            userRefreshed = await _userManager.FindByEmailAsync(defaultUserEmail);
            Assert.IsTrue(userRefreshed.Email == defaultUserEmail);
            Assert.IsTrue(userRefreshed.NormalizedEmail == defaultUserEmail.ToUpperInvariant());
        }

        [TestMethod]
        public async Task UserMiscValuesChange()
        {
            var user = await _userManager.FindByNameAsync(defaultUserName);
            user.AccessFailedCount = 7;
            user.EmailConfirmed = true;
            user.PhoneNumber = "123-123-1234";
            user.PhoneNumberConfirmed = true;

            IdentityResult resultChange = await _userManager.UpdateAsync(user);
            Assert.IsTrue(resultChange.Succeeded);

            var userRefreshed = await _userManager.FindByNameAsync(defaultUserName);
            Assert.IsTrue(userRefreshed.AccessFailedCount == 7);
            Assert.IsTrue(userRefreshed.EmailConfirmed);
            Assert.IsTrue(userRefreshed.PhoneNumber == "123-123-1234");
            Assert.IsTrue(userRefreshed.PhoneNumberConfirmed);

            user.AccessFailedCount = 0;
            user.EmailConfirmed = false;
            user.PhoneNumber = "";
            user.PhoneNumberConfirmed = false;

            IdentityResult resultChangeBack = await _userManager.UpdateAsync(user);
            Assert.IsTrue(resultChangeBack.Succeeded);

            userRefreshed = await _userManager.FindByNameAsync(defaultUserName);
            Assert.IsTrue(userRefreshed.AccessFailedCount == 0);
            Assert.IsFalse(userRefreshed.EmailConfirmed);
            Assert.IsTrue(String.IsNullOrEmpty(userRefreshed.PhoneNumber));
            Assert.IsFalse(userRefreshed.PhoneNumberConfirmed);
        }
        #endregion

        #region User claims
        [TestMethod]
        public async Task AddClaimForUserAndReplaceClaim()
        {
            var user = await _userManager.FindByNameAsync(defaultUserName);

            Claim claim = new Claim(claimType, claim1Value);
            IdentityResult addClaimResult = await _userManager.AddClaimAsync(user, claim);
            Assert.IsTrue(addClaimResult.Succeeded);

            IList<Claim> claimsList = await _userManager.GetClaimsAsync(user);
            Claim retrievedClaim1 = claimsList.Where(x => x.Type == claimType && x.Value == claim1Value).FirstOrDefault();
            Assert.IsTrue(retrievedClaim1.Type == claimType && retrievedClaim1.Value == claim1Value);

            Claim newClaim = new Claim(claimType, claim2Value);
            IdentityResult replaceClaimResult = await _userManager.ReplaceClaimAsync(user, claim, newClaim);
            Assert.IsTrue(replaceClaimResult.Succeeded);

            claimsList = await _userManager.GetClaimsAsync(user);
            Claim retrievedClaim2 = claimsList.Where(x => x.Type == claimType && x.Value == claim2Value).FirstOrDefault();
            Assert.IsTrue(retrievedClaim2.Type == claimType && retrievedClaim2.Value == claim2Value);

            //delete claim for the user
            IdentityResult result = await _userManager.RemoveClaimAsync(user, newClaim);
            Assert.IsTrue(result.Succeeded);
        }

        [TestMethod]
        public async Task AddMultipleClaimsForUser()
        {
            var user = await _userManager.FindByNameAsync(defaultUserName);

            IList<Claim> addMultipleClaims = new List<Claim>();
            Claim claim1 = new Claim(claimType, claim1Value);
            Claim claim2 = new Claim(claimType, claim2Value);
            addMultipleClaims.Add(claim1);
            addMultipleClaims.Add(claim2);
            IdentityResult result = await _userManager.AddClaimsAsync(user, addMultipleClaims);
            Assert.IsTrue(result.Succeeded);

            IList<Claim> claimsList = await _userManager.GetClaimsAsync(user);
            Claim retrievedClaim1 = claimsList.Where(x => x.Type == claimType && x.Value == claim1Value).FirstOrDefault();
            Claim retrievedClaim2 = claimsList.Where(x => x.Type == claimType && x.Value == claim2Value).FirstOrDefault();
            Assert.IsTrue(retrievedClaim1.Type == claimType && retrievedClaim1.Value == claim1Value);
            Assert.IsTrue(retrievedClaim2.Type == claimType && retrievedClaim2.Value == claim2Value);

            //delete claims for the user
            result = await _userManager.RemoveClaimsAsync(user, claimsList);
            Assert.IsTrue(result.Succeeded);
        }

        [TestMethod]
        public async Task GetUsersForAClaim()
        {
            Claim claim = new Claim(claimType, claim1Value);

            //create two users
            ApplicationUser user1 = new ApplicationUser()
            {
                UserName = user1Name,
                Email = user1Email
            };
            var result = await _userManager.CreateAsync(user1, defaultPassword);
            Assert.IsTrue(result.Succeeded);

            ApplicationUser user2 = new ApplicationUser()
            {
                UserName = user2Name,
                Email = user2Email
            };
            result = await _userManager.CreateAsync(user2, defaultPassword);
            Assert.IsTrue(result.Succeeded);

            //users created, add claim
            result = await _userManager.AddClaimAsync(user1, claim);
            Assert.IsTrue(result.Succeeded);

            result = await _userManager.AddClaimAsync(user2, claim);
            Assert.IsTrue(result.Succeeded);

            //see if we stored them
            IList<ApplicationUser> users = await _userManager.GetUsersForClaimAsync(claim);
            Assert.IsTrue(users.Where(x => x.UserName == user1Name & x.Email == user1Email).Count() == 1);
            Assert.IsTrue(users.Where(x => x.UserName == user2Name & x.Email == user2Email).Count() == 1);

            //should only be two users with this claim
            Assert.IsTrue(users.Count() == 2);

            //delete claims for the user
            result = await _userManager.RemoveClaimAsync(user1, claim);
            Assert.IsTrue(result.Succeeded);
            result = await _userManager.RemoveClaimAsync(user2, claim);
            Assert.IsTrue(result.Succeeded);

            //should now be zero users with this claim
            users = await _userManager.GetUsersForClaimAsync(claim);
            Assert.IsTrue(users.Count() == 0);
        }
        #endregion

        #region lockout store
        [TestMethod]
        public async Task UserLockoutEnabled()
        {
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);
            user.LockoutEnabled = true;
            IdentityResult result = await _userManager.UpdateAsync(user);
            Assert.IsTrue(result.Succeeded);

            var userRefreshed = await _userManager.FindByEmailAsync(defaultUserEmail);
            Assert.IsTrue(userRefreshed.LockoutEnabled == true);

            //change it back
            user.LockoutEnabled = false;
            IdentityResult resultUnlock = await _userManager.UpdateAsync(user);
            Assert.IsTrue(resultUnlock.Succeeded);

            userRefreshed = await _userManager.FindByEmailAsync(defaultUserEmail);
            Assert.IsTrue(userRefreshed.LockoutEnabled == false);
        }

        [TestMethod]
        public async Task UserLockoutEndChange()
        {
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);
            //one hour in the past
            user.LockoutEnd = DateTime.UtcNow.AddHours(-1);
            IdentityResult resultInThePast = await _userManager.UpdateAsync(user);
            Assert.IsTrue(resultInThePast.Succeeded);

            var userRefreshed = await _userManager.FindByEmailAsync(defaultUserEmail);
            //it should be in the past
            Assert.IsTrue(userRefreshed.LockoutEnd < DateTime.UtcNow);

            //one hour in the future
            user.LockoutEnd = DateTime.UtcNow.AddHours(1);
            IdentityResult resultInTheFuture = await _userManager.UpdateAsync(user);
            Assert.IsTrue(resultInTheFuture.Succeeded);

            userRefreshed = await _userManager.FindByEmailAsync(defaultUserEmail);
            //it should be in the future
            Assert.IsTrue(userRefreshed.LockoutEnd > DateTime.UtcNow);

            //allow the user again
            user.LockoutEnabled = false;
            user.LockoutEnd = null;
            IdentityResult resultUnlock = await _userManager.UpdateAsync(user);
            Assert.IsTrue(resultUnlock.Succeeded);

            userRefreshed = await _userManager.FindByEmailAsync(defaultUserEmail);
            Assert.IsTrue(userRefreshed.LockoutEnabled == false);
        }
        #endregion

        #region login store
        [TestMethod]
        public async Task UserLoginCreateAndFindItViaCollection()
        {
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);

            user.LoginProvider = loginProvider;
            user.LoginProviderDisplayName = loginProviderDisplayName;
            user.LoginProviderKey = loginProviderKey;

            UserLoginInfo userLoginInfo = new UserLoginInfo(user.LoginProvider, user.LoginProviderKey, user.LoginProviderDisplayName);
            IdentityResult result = await _userManager.AddLoginAsync(user, userLoginInfo);
            Assert.IsTrue(result.Succeeded);

            IList<UserLoginInfo> userLoginInfoList = await _userManager.GetLoginsAsync(user);
            Assert.IsNotNull(userLoginInfoList);

            bool foundMatch = false;
            foreach (UserLoginInfo loginInfo in userLoginInfoList)
            {
                bool match = loginInfo.LoginProvider == user.LoginProvider && loginInfo.ProviderKey == user.LoginProviderKey && loginInfo.ProviderDisplayName == user.LoginProviderDisplayName;
                if (match)
                {
                    foundMatch = true;
                }
            }
            Assert.IsTrue(foundMatch);

            IdentityResult removeLoginResult = await _userManager.RemoveLoginAsync(user, loginProvider, loginProviderKey);
            Assert.IsTrue(removeLoginResult.Succeeded);
        }
        [TestMethod]
        public async Task CreateUserLoginFindItDeleteIt()
        {
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);

            user.LoginProvider = loginProvider;
            user.LoginProviderDisplayName = loginProviderDisplayName;
            user.LoginProviderKey = loginProviderKey;

            UserLoginInfo userLoginInfo = new UserLoginInfo(user.LoginProvider, user.LoginProviderKey, user.LoginProviderDisplayName);
            IdentityResult result = await _userManager.AddLoginAsync(user, userLoginInfo);
            Assert.IsTrue(result.Succeeded);

            ApplicationUser userFetchByLogin = await _userManager.FindByLoginAsync(user.LoginProvider, user.LoginProviderKey);
            Assert.IsNotNull(userFetchByLogin);

            Assert.IsTrue(userFetchByLogin.Id == user.Id);
            Assert.IsTrue(userFetchByLogin.UserName == user.UserName);

            IdentityResult removeLoginResult = await _userManager.RemoveLoginAsync(user, loginProvider, loginProviderKey);
            Assert.IsTrue(removeLoginResult.Succeeded);
        }
        [TestMethod]
        public async Task CheckUniqueConstraintUserLogins()
        {
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);
            Assert.IsNotNull(user);

            user.LoginProvider = loginProvider;
            user.LoginProviderDisplayName = loginProviderDisplayName;
            user.LoginProviderKey = loginProviderKey;

            //should succeed
            UserLoginInfo userLoginInfo1 = new UserLoginInfo(user.LoginProvider, user.LoginProviderKey, user.LoginProviderDisplayName);
            IdentityResult result1 = await _userManager.AddLoginAsync(user, userLoginInfo1);
            Assert.IsTrue(result1.Succeeded);

            //should fail, already exists
            UserLoginInfo userLoginInfo2 = new UserLoginInfo(user.LoginProvider, user.LoginProviderKey, user.LoginProviderDisplayName);
            IdentityResult result2 = await _userManager.AddLoginAsync(user, userLoginInfo2);
            Assert.IsTrue(!result2.Succeeded);

            IdentityResult removeLoginResult = await _userManager.RemoveLoginAsync(user, loginProvider, loginProviderKey);
            Assert.IsTrue(removeLoginResult.Succeeded);
        }
        #endregion

        #region two factor recovery code store
        [TestMethod]
        public async Task GenerateOneCodeAndRedeemIt()
        {
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);

            user.LoginProvider = loginProvider;
            user.LoginProviderDisplayName = loginProviderDisplayName;
            user.LoginProviderKey = loginProviderKey;
            user.LoginRecoveryTokenKey = loginRecoveryTokenKey;

            IEnumerable<string> oneCode = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 1);
            Assert.IsTrue(oneCode.Count() == 1);

            int oneCodeCount = await _userManager.CountRecoveryCodesAsync(user);
            Assert.IsTrue(oneCodeCount == 1);

            string theSingleCode = oneCode.FirstOrDefault();

            IdentityResult result = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, theSingleCode);
            Assert.IsTrue(result.Succeeded);

            //code was redeemed, so it should be empty
            int zeroCodeCount = await _userManager.CountRecoveryCodesAsync(user);
            Assert.IsTrue(zeroCodeCount == 0);
        }

        [TestMethod]
        public async Task CreateTwoFactorCodesAndCount()
        {
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);

            user.LoginProvider = loginProvider;
            user.LoginProviderDisplayName = loginProviderDisplayName;
            user.LoginProviderKey = loginProviderKey;
            user.LoginRecoveryTokenKey = loginRecoveryTokenKey;

            IEnumerable<string> tenCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            Assert.IsTrue(tenCodes.Count() == 10);
            int tenCodesCount = await _userManager.CountRecoveryCodesAsync(user);
            Assert.IsTrue(tenCodesCount == 10);

            IEnumerable<string> fiveCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 5);
            Assert.IsTrue(fiveCodes.Count() == 5);
            int fiveCodesCount = await _userManager.CountRecoveryCodesAsync(user);
            Assert.IsTrue(fiveCodesCount == 5);
        }
        #endregion

        #region token get/set
        [TestMethod]
        public async Task AddRandomTokensFindThemAndDelete()
        {
            //set, remove, get
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);

            user.LoginProvider = loginProvider;
            user.LoginProviderDisplayName = loginProviderDisplayName;
            user.LoginProviderKey = loginProviderKey;
            user.LoginRecoveryTokenKey = loginRecoveryTokenKey;

            var newToken1 = await _userManager.SetAuthenticationTokenAsync(user, user.LoginProvider, "A.Random.Login.Provider.TokenName1", "A.Random.Login.Provider.TokenValue1");
            string authenticationToken1 = await _userManager.GetAuthenticationTokenAsync(user, user.LoginProvider, "A.Random.Login.Provider.TokenName1");
            Assert.IsTrue(authenticationToken1 == "A.Random.Login.Provider.TokenValue1");

            var newToken2 = await _userManager.SetAuthenticationTokenAsync(user, user.LoginProvider, "A.Random.Login.Provider.TokenName2", "A.Random.Login.Provider.TokenValue2");
            string authenticationToken2 = await _userManager.GetAuthenticationTokenAsync(user, user.LoginProvider, "A.Random.Login.Provider.TokenName2");
            Assert.IsTrue(authenticationToken2 == "A.Random.Login.Provider.TokenValue2");

            var newToken3 = await _userManager.SetAuthenticationTokenAsync(user, user.LoginProvider, "A.Random.Login.Provider.TokenName3", "A.Random.Login.Provider.TokenValue3");
            string authenticationToken3 = await _userManager.GetAuthenticationTokenAsync(user, user.LoginProvider, "A.Random.Login.Provider.TokenName3");
            Assert.IsTrue(authenticationToken3 == "A.Random.Login.Provider.TokenValue3");

            IdentityResult result1 = await _userManager.RemoveAuthenticationTokenAsync(user, user.LoginProvider, "A.Random.Login.Provider.TokenName1");
            Assert.IsTrue(result1.Succeeded);
            IdentityResult result2 = await _userManager.RemoveAuthenticationTokenAsync(user, user.LoginProvider, "A.Random.Login.Provider.TokenName2");
            Assert.IsTrue(result2.Succeeded);
            IdentityResult result3 = await _userManager.RemoveAuthenticationTokenAsync(user, user.LoginProvider, "A.Random.Login.Provider.TokenName3");
            Assert.IsTrue(result3.Succeeded);
        }
        #endregion

        #region authenticator key
        [TestMethod]
        public async Task SetAuthenticationKeyTokenFindItDeleteIt()
        {
            var user = await _userManager.FindByEmailAsync(defaultUserEmail);

            user.LoginProvider = loginProvider;
            user.LoginProviderDisplayName = loginProviderDisplayName;
            user.LoginProviderKey = loginProviderKey;
            user.LoginRecoveryTokenKey = loginRecoveryTokenKey;

            IdentityResult result = await _userManager.SetAuthenticationTokenAsync(user, loginProvider, authenticatorKeyTokenName, authenticatorKeyTokenValue);
            Assert.IsTrue(result.Succeeded);

            string authenticatorToken = await _userManager.GetAuthenticationTokenAsync(user, loginProvider, authenticatorKeyTokenName);
            Assert.IsTrue(authenticatorToken == authenticatorKeyTokenValue);

            IdentityResult deleteResult = await _userManager.RemoveAuthenticationTokenAsync(user, loginProvider, authenticatorKeyTokenName);
            Assert.IsTrue(result.Succeeded);
        }
        #endregion
        
        [TestCleanup]
        public async Task CleanUp()
        {
            //delete default test user, roles, claims, etc. that we might have missed
            //so even when we're running the tests and we screw up and a test fails,
            //we're not left with inconsistent database state on next test run

            //delete default user
            var deleteDefaultUser = await _userManager.FindByEmailAsync(defaultUserEmail);
            if (deleteDefaultUser != null)
            {
                await _userManager.DeleteAsync(deleteDefaultUser);
            }

            //delete 
            var user1ToDelete = await _userManager.FindByEmailAsync(user1Email);
            if (user1ToDelete != null)
            {
                var deleteUser1 = await _userManager.DeleteAsync(user1ToDelete);
                Assert.IsTrue(deleteUser1.Succeeded);
            }

            var user2ToDelete = await _userManager.FindByEmailAsync(user2Email);
            if (user2ToDelete != null)
            {
                var deleteUser2 = await _userManager.DeleteAsync(user2ToDelete);
                Assert.IsTrue(deleteUser2.Succeeded);
            }

            //delete users from IQueryable test
            var user1Refetch = await _userManager.FindByNameAsync("a1");
            if (user1Refetch != null)
            {
                await _userManager.DeleteAsync(user1Refetch);
            }
            var user2Refetch = await _userManager.FindByNameAsync("a2");
            if (user2Refetch != null)
            {
                await _userManager.DeleteAsync(user2Refetch);
            }
            var user3Refetch = await _userManager.FindByNameAsync("a3");
            if (user3Refetch != null)
            {
                await _userManager.DeleteAsync(user3Refetch);
            }
            var user4Refetch = await _userManager.FindByNameAsync("a4");
            if (user4Refetch != null)
            {
                await _userManager.DeleteAsync(user4Refetch);
            }

            //delete the defaultAdminRole
            ApplicationRole deleteRole = await _roleManager.FindByNameAsync(defaultAdminRole);
            if (deleteRole != null)
            {
                await _roleManager.DeleteAsync(deleteRole);
            }

            await base.Cleanup();
        }
    }
}
