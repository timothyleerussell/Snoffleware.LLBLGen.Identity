using Microsoft.AspNetCore.Identity;
using SD.LLBLGen.Pro.QuerySpec;
using SD.LLBLGen.Pro.QuerySpec.Adapter;
using Snoffleware.LLBLGen.Identity.Core.Data.DatabaseSpecific;
using Snoffleware.LLBLGen.Identity.Core.Data.EntityClasses;
using Snoffleware.LLBLGen.Identity.Core.Data.FactoryClasses;
using Snoffleware.LLBLGen.Identity.Core.Data.HelperClasses;
using Snoffleware.LLBLGen.Identity.Core.Data.Linq;
using Snoffleware.LLBLGen.Identity.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Snoffleware.LLBLGen.Identity.Core
{
    //goal here is to have parity with the database schema and functionality
    //of net core identity but with LLBLGen plugged in as the ORM
    public class UserStore :
        //IProtectedUserStore<ApplicationUser> is not implemented because I haven't spent the time
        //to figure out how to implement this yet.
        //
        //Need to check for the ProtectPersonalData attribute
        //and encrypt/decrypt fields but details, don't need it for my case but would be a good
        //contribution by someone who does...
        //
        //I think this is not a problem for most users...
        //You can encrypt the db at rest with azure encryption and you can apply column level permissions
        //Encrypting at the field level prevents even the third party from having access, so would be useful
        //for cases when privacy from even trusted partners is required
        //Don't need it for my use case, so I am not going to spend the time figuring out how to 
        //implement it.
        //
        //I think I have full coverage (minus IProtectedUserStore) of the basic identity pieces
        //using LLBLGen Pro framework as the ORM

        IQueryableUserStore<ApplicationUser>,
        IUserAuthenticationTokenStore<ApplicationUser>,
        IUserAuthenticatorKeyStore<ApplicationUser>,
        IUserClaimStore<ApplicationUser>,
        IUserEmailStore<ApplicationUser>,
        IUserLockoutStore<ApplicationUser>,
        IUserLoginStore<ApplicationUser>,
        IUserPasswordStore<ApplicationUser>,
        IUserPhoneNumberStore<ApplicationUser>,
        IUserRoleStore<ApplicationUser>,
        IUserSecurityStampStore<ApplicationUser>,
        IUserStore<ApplicationUser>,
        IUserTwoFactorRecoveryCodeStore<ApplicationUser>,
        IUserTwoFactorStore<ApplicationUser>
    {
        IQueryable<ApplicationUser> IQueryableUserStore<ApplicationUser>.Users
        {
            get
            {
                DataAccessAdapter adapter = new DataAccessAdapter();
                try
                {                                       
                    var md = new LinqMetaData(adapter);
                    var q = from userEntity in md.AspNetUser
                            select new ApplicationUser()
                            {
                                Id = userEntity.Id,
                                UserName = userEntity.UserName,
                                NormalizedUserName = userEntity.NormalizedUserName,
                                Email = userEntity.Email,
                                NormalizedEmail = userEntity.NormalizedEmail,
                                EmailConfirmed = userEntity.EmailConfirmed,
                                PasswordHash = userEntity.PasswordHash,
                                SecurityStamp = userEntity.SecurityStamp,
                                ConcurrencyStamp = userEntity.ConcurrencyStamp,
                                PhoneNumber = userEntity.PhoneNumber,
                                PhoneNumberConfirmed = userEntity.PhoneNumberConfirmed,
                                TwoFactorEnabled = userEntity.TwoFactorEnabled,
                                LockoutEnd = userEntity.LockoutEnd,
                                LockoutEnabled = userEntity.LockoutEnabled,
                                AccessFailedCount = userEntity.AccessFailedCount,
                                ProfileImage = userEntity.ProfileImage
                            };
                    return q;
                }
                finally
                {
                    adapter.CloseConnection();

                    //TODO: displose the adapter in the test after accessing the IQueryable object

                    //Using a using statement disposes the adapter, so I unrolled it to a try/finally but close the connection only.
                    //rather than allowing the using statement to dispose the adapter...works in the tests now but side effects?

                    //System.ObjectDisposedException: This DataAccessAdapter instance has already been disposed, you can't use it for further persistence activity
                    //Object name: 'DataAccessAdapterBase'.
                    //adapter.Dispose();
                }
            }
        }
        public async Task AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();

                foreach (Claim claim in claims)
                {
                    var q = qf.AspNetUserClaim
                        .Where(AspNetUserClaimFields.UserId.Equal(user.Id)
                        .And(AspNetUserClaimFields.ClaimValue.Equal(claim.Value))
                        .And(AspNetUserClaimFields.ClaimType.Equal(claim.Type)));

                    var fetchedClaim = await adapter.FetchFirstAsync(q, cancellationToken);

                    if (fetchedClaim != null)
                    {
                        continue;
                    }

                    AspNetUserClaimEntity claimEntity = new AspNetUserClaimEntity();
                        claimEntity.UserId = user.Id;
                        claimEntity.ClaimType = claim.Type;
                        claimEntity.ClaimValue = claim.Value;

                    await adapter.SaveEntityAsync(claimEntity, cancellationToken);
                }
            }
        }
        public async Task AddLoginAsync(ApplicationUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserLogin
                    .Where(AspNetUserLoginFields.UserId.Equal(user.Id)
                    .And(AspNetUserLoginFields.LoginProvider.Equal(login.LoginProvider))
                    .And(AspNetUserLoginFields.ProviderKey.Equal(login.ProviderKey)));

                var userLogin = await adapter.FetchFirstAsync(q, cancellationToken);

                if (userLogin == null)
                {
                    AspNetUserLoginEntity userLoginEntity = new AspNetUserLoginEntity();
                    userLoginEntity.UserId = user.Id;
                    userLoginEntity.LoginProvider = login.LoginProvider;
                    userLoginEntity.ProviderDisplayName = login.ProviderDisplayName;
                    userLoginEntity.ProviderKey = login.ProviderKey;

                    await adapter.SaveEntityAsync(userLoginEntity, cancellationToken);
                }
            }
        }
        public async Task AddToRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetRole.Where(AspNetRoleFields.NormalizedName.Equal(roleName));

                var role = await adapter.FetchFirstAsync(q, cancellationToken);

                if (role != null)
                {
                    AspNetUserRoleEntity userRole = new AspNetUserRoleEntity();
                    userRole.UserId = user.Id;
                    userRole.RoleId = role.Id;
                
                    await adapter.SaveEntityAsync(userRole, cancellationToken);
                }
            }
        }
        public async Task<int> CountCodesAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            string token = await GetTokenAsync(user, user.LoginProvider, user.LoginRecoveryTokenKey, cancellationToken);

            //if a single code, this should return 1
            //if not empty, we have at least one token, get the ; count and add 1 otherwise return 0
            if (!String.IsNullOrWhiteSpace(token))
            {
                return token.Count(c => c == ';') + 1;
            }
            return 0;
        }
        public async Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            using (var adapter = new DataAccessAdapter())
            {
                AspNetUserEntity userEntity = new AspNetUserEntity();
                userEntity.Id = user.Id;
                userEntity.UserName = user.UserName;
                userEntity.NormalizedUserName = user.UserName.ToUpper();
                userEntity.Email = user.Email;
                userEntity.NormalizedEmail = user.Email.ToUpper();
                userEntity.EmailConfirmed = user.EmailConfirmed;
                userEntity.PasswordHash = user.PasswordHash;
                userEntity.SecurityStamp = user.SecurityStamp;
                userEntity.ConcurrencyStamp = user.ConcurrencyStamp;
                userEntity.PhoneNumber = user.PhoneNumber;
                userEntity.PhoneNumberConfirmed = user.PhoneNumberConfirmed;
                userEntity.TwoFactorEnabled = user.TwoFactorEnabled;
                userEntity.LockoutEnd = user.LockoutEnd;
                userEntity.LockoutEnabled = user.LockoutEnabled;
                userEntity.AccessFailedCount = user.AccessFailedCount;
                userEntity.ProfileImage = user.ProfileImage;

                bool saved = await adapter.SaveEntityAsync(userEntity, cancellationToken);
                if (!saved)
                {
                    return IdentityResult.Failed(new IdentityError { Description = $"Could not insert user {user.Id}, {user.Email}." });
                }
            }

            return IdentityResult.Success;
        }
        public async Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUser.Where(AspNetUserFields.Id.Equal(user.Id));

                var userEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                if (userEntity != null)
                {
                    bool deleted = await adapter.DeleteEntityAsync(userEntity, cancellationToken);

                    if (!deleted)
                    {
                        return IdentityResult.Failed(new IdentityError { Description = $"Could not delete user {user.Id}, {user.Email}." });
                    }
                }
            }
            return IdentityResult.Success;
        }

        //https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-3.0/ms244737(v=vs.80)?redirectedfrom=MSDN
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                //free managed resources
            }
        }
        public async Task<ApplicationUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.Create()
                    .Where(AspNetUserFields.NormalizedEmail.Equal(normalizedEmail))
                    .Select<ApplicationUser, AspNetUserFields>();

                var user = await adapter.FetchFirstAsync(q, cancellationToken);
                    
                return user;
            }            
        }
        public async Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.Create()
                    .Where(AspNetUserFields.Id.Equal(userId))
                    .Select<ApplicationUser, AspNetUserFields>();

                var user = await adapter.FetchFirstAsync(q, cancellationToken);

                return user;
            }
        }
        public async Task<ApplicationUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserLogin
                    .Where(AspNetUserLoginFields.LoginProvider.Equal(loginProvider)
                    .And(AspNetUserLoginFields.ProviderKey.Equal(providerKey)));

                var result = await adapter.FetchFirstAsync(q, cancellationToken);

                ApplicationUser user = null;

                if (result != null)
                {
                    user = await FindByIdAsync(result.UserId, cancellationToken);
                }
                return user;
            }
        }
        public async Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.Create()
                    .Where(AspNetUserFields.NormalizedUserName.Equal(normalizedUserName))
                    .Select<ApplicationUser, AspNetUserFields>();

                var user = await adapter.FetchFirstAsync(q, cancellationToken);

                return user;
            }
        }
        public Task<int> GetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.AccessFailedCount);
        }
        public async Task<string> GetAuthenticatorKeyAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string token = await GetTokenAsync(user, user.LoginProvider, user.AuthenticatorKeyTokenName, cancellationToken);

            return token ?? string.Empty;
        }
        public async Task<IList<Claim>> GetClaimsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserClaim.Where(AspNetUserClaimFields.UserId.Equal(user.Id));
                var userClaims = await adapter.FetchQueryAsync(q, cancellationToken);
                return userClaims.Cast<AspNetUserClaimEntity>().Select(uc => new Claim(uc.ClaimType, uc.ClaimValue)).ToList();
            }
        }
        public Task<string> GetEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Email);
        }
        public Task<bool> GetEmailConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.EmailConfirmed);
        }
        public Task<bool> GetLockoutEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.LockoutEnabled);
        }
        public Task<DateTimeOffset?> GetLockoutEndDateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            DateTimeOffset? dateTimeOffset = user.LockoutEnd;
            return Task.FromResult(dateTimeOffset);
        }
        public async Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserLogin.Where(AspNetUserLoginFields.UserId.Equal(user.Id));
                var userLogins = await adapter.FetchQueryAsync(q, cancellationToken);
                return userLogins.Cast<AspNetUserLoginEntity>()
                    .Select(ul => new UserLoginInfo(ul.LoginProvider, ul.ProviderKey, ul.ProviderDisplayName)).ToList();
            }
        }
        public Task<string> GetNormalizedEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.NormalizedEmail);
        }
        public Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.NormalizedUserName);
        }
        public Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash);
        }
        public Task<string> GetPhoneNumberAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PhoneNumber);
        }
        public Task<bool> GetPhoneNumberConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task<string> GetProfileImageAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.ProfileImage);
        }
        public async Task<IList<string>> GetRolesAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();

                var q = qf.AspNetRole.From(QueryTarget
                    .InnerJoin(AspNetUserRoleEntity.Relations.AspNetRoleEntityUsingRoleId))
                    .Where(AspNetUserRoleFields.UserId.Equal(user.Id));

                var userRoles = await adapter.FetchQueryAsync(q, cancellationToken);

                return userRoles.Cast<AspNetRoleEntity>().Select(ur => ur.NormalizedName).ToList();
            }
        }
        public Task<string> GetSecurityStampAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.SecurityStamp);
        }
        public async Task<string> GetTokenAsync(ApplicationUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserToken
                    .Where(AspNetUserTokenFields.UserId.Equal(user.Id)
                    .And(AspNetUserTokenFields.LoginProvider.Equal(user.LoginProvider)
                    .And(AspNetUserTokenFields.Name.Equal(name))));

                var tokenEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                return tokenEntity?.Value ?? string.Empty;
            }
        }
        public Task<bool> GetTwoFactorEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.TwoFactorEnabled);
        }
        public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Id);
        }
        public Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserName);
        }
        public async Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUser.From(QueryTarget
                    .InnerJoin(AspNetUserClaimEntity.Relations.AspNetUserEntityUsingUserId))
                    .Where(AspNetUserClaimFields.ClaimType.Equal(claim.Type)
                    .And(AspNetUserClaimFields.ClaimValue.Equal(claim.Value)))
                    .Select(ProjectionLambdaCreator.Create<ApplicationUser, AspNetUserFields>());

                var users = await adapter.FetchQueryAsync(q, cancellationToken);

                return users;
            }
        }
        public async Task<IList<ApplicationUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUser.From(QueryTarget
                    .InnerJoin(AspNetRoleEntity.Relations.AspNetUserRoleEntityUsingRoleId)
                    .InnerJoin(AspNetUserRoleEntity.Relations.AspNetUserEntityUsingUserId))
                    .Where(AspNetRoleFields.Name.Equal(roleName))
                    .AndWhere(AspNetUserRoleFields.RoleId.Equal(AspNetRoleFields.Id))
                    .Select(ProjectionLambdaCreator.Create<ApplicationUser, AspNetUserFields>());

                var users = await adapter.FetchQueryAsync(q, cancellationToken);

                return users;
            }
        }
        public Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash != null);
        }
        public Task<int> IncrementAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }
        public async Task<bool> IsInRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IList<string> roles = await GetRolesAsync(user, cancellationToken);
            return roles.Contains(roleName);
        }
        public async Task<bool> RedeemCodeAsync(ApplicationUser user, string code, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string token = await GetTokenAsync(user, user.LoginProvider, user.LoginRecoveryTokenKey, cancellationToken);

            if (token == null)
            {
                return false;
            }

            var recoveryCodes = token.Split(";");
            if (recoveryCodes.Contains(code))
            {
                var updatedCodes = new List<string>(recoveryCodes.Where(x => x != code));
                await ReplaceCodesAsync(user, updatedCodes, cancellationToken);
                return true;
            }

            return false;
        }
        public async Task RemoveClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            IList<AspNetUserClaimEntity> userClaimsList = new List<AspNetUserClaimEntity>();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserClaim.Where(AspNetUserClaimFields.UserId.Equal(user.Id));

                var userClaims = await adapter.FetchQueryAsync(q, cancellationToken);

                foreach (AspNetUserClaimEntity claim in userClaims)
                {
                    if (claims.Where(c => c.Type == claim.ClaimType && c.Value == claim.ClaimValue).Count() == 1)
                    {
                        userClaimsList.Add(claim);
                    }
                }

                foreach (AspNetUserClaimEntity claimToDelete in userClaimsList)
                {
                    await adapter.DeleteEntityAsync(claimToDelete);
                }
            }
        }
        public async Task RemoveFromRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var roleQ = qf.AspNetRole.Where(AspNetRoleFields.NormalizedName.Equal(roleName));

                var roleEntity = adapter.FetchFirstAsync(roleQ, cancellationToken);

                if (roleEntity != null)
                {
                    var q = qf.AspNetUserRole
                        .Where(AspNetUserRoleFields.RoleId.Equal(roleEntity.Id)
                        .And(AspNetUserRoleFields.UserId.Equal(user.Id)));

                    var userRoles = await adapter.FetchQueryAsync(q, cancellationToken);

                    foreach (AspNetUserRoleEntity userRole in userRoles)
                    {
                        await adapter.DeleteEntityAsync(userRole);
                    }
                }
            }
        }
        public async Task RemoveLoginAsync(ApplicationUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserLogin
                    .Where(AspNetUserLoginFields.UserId.Equal(user.Id).
                    And(AspNetUserLoginFields.LoginProvider.Equal(loginProvider))
                    .And(AspNetUserLoginFields.ProviderKey.Equal(providerKey)));

                var loginEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                if (loginEntity != null)
                {
                    await adapter.DeleteEntityAsync(loginEntity);
                }
            }
        }
        public async Task RemoveTokenAsync(ApplicationUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserToken
                    .Where(AspNetUserTokenFields.UserId.Equal(user.Id)
                    .And(AspNetUserTokenFields.LoginProvider.Equal(loginProvider))
                    .And(AspNetUserTokenFields.Name.Equal(name)));

                var tokenEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                if (tokenEntity != null)
                {
                    await adapter.DeleteEntityAsync(tokenEntity);
                }
            }
        }
        public async Task ReplaceClaimAsync(ApplicationUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserClaim
                    .Where(AspNetUserClaimFields.UserId.Equal(user.Id)
                    .And(AspNetUserClaimFields.ClaimValue.Equal(claim.Value))
                    .And(AspNetUserClaimFields.ClaimType.Equal(claim.Type)));

                var claimEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                if (claimEntity != null)
                {
                    claimEntity.UserId = user.Id;
                    claimEntity.ClaimValue = newClaim.Value;
                    claimEntity.ClaimType = newClaim.Type;

                    await adapter.SaveEntityAsync(claimEntity, cancellationToken);
                }
            }
        }
        public async Task ReplaceCodesAsync(ApplicationUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserToken
                    .Where(AspNetUserTokenFields.UserId.Equal(user.Id)
                    .And(AspNetUserTokenFields.LoginProvider.Equal(user.LoginProvider))
                    .And(AspNetUserTokenFields.Name.Equal(user.LoginRecoveryTokenKey)));

                var userTokenEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                if (userTokenEntity == null)
                {
                    userTokenEntity = new AspNetUserTokenEntity();
                }
                userTokenEntity.UserId = user.Id;
                userTokenEntity.LoginProvider = user.LoginProvider;
                userTokenEntity.Name = user.LoginRecoveryTokenKey;
                userTokenEntity.Value = string.Join(";", recoveryCodes);

                await adapter.SaveEntityAsync(userTokenEntity, cancellationToken);
            }
        }
        public Task ResetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            user.AccessFailedCount = 0;
            return Task.CompletedTask;
        }
        public Task SetAuthenticatorKeyAsync(ApplicationUser user, string key, CancellationToken cancellationToken)
        {
            return SetTokenAsync(user, user.LoginProvider, user.AuthenticatorKeyTokenName, key, cancellationToken);
        }
        public Task SetEmailAsync(ApplicationUser user, string email, CancellationToken cancellationToken)
        {
            user.Email = email;
            return Task.CompletedTask;
        }
        public Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.EmailConfirmed = confirmed;
            return Task.CompletedTask;
        }
        public Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            user.LockoutEnabled = enabled;
            return Task.CompletedTask;
        }
        public Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            user.LockoutEnd = lockoutEnd?.UtcDateTime;
            return Task.CompletedTask;
        }
        public Task SetNormalizedEmailAsync(ApplicationUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            user.NormalizedEmail = normalizedEmail;
            return Task.CompletedTask;
        }
        public Task SetNormalizedUserNameAsync(ApplicationUser user, string normalizedName, CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
            return Task.CompletedTask;
        }
        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;
            return Task.CompletedTask;
        }
        public Task SetPhoneNumberAsync(ApplicationUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            user.PhoneNumber = phoneNumber;
            return Task.CompletedTask;
        }
        public Task SetProfileImageAsync(ApplicationUser user, string profileImage)
        {
            user.ProfileImage = profileImage;
            return Task.CompletedTask;
        }

        public Task SetPhoneNumberConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.PhoneNumberConfirmed = confirmed;
            return Task.CompletedTask;
        }
        public Task SetSecurityStampAsync(ApplicationUser user, string stamp, CancellationToken cancellationToken)
        {
            user.SecurityStamp = stamp;
            return Task.CompletedTask;
        }
        public async Task SetTokenAsync(ApplicationUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUserToken
                    .Where(AspNetUserTokenFields.UserId.Equal(user.Id)
                    .And(AspNetUserTokenFields.LoginProvider.Equal(loginProvider))
                    .And(AspNetUserTokenFields.Name.Equal(name)));

                var userToken = await adapter.FetchFirstAsync(q, cancellationToken);

                if (userToken == null)
                {
                    userToken = new AspNetUserTokenEntity();
                }
                userToken.UserId = user.Id;
                userToken.LoginProvider = user.LoginProvider;
                userToken.Name = name;
                userToken.Value = value;

                await adapter.SaveEntityAsync(userToken, cancellationToken);
            }
        }
        public Task SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            user.TwoFactorEnabled = enabled;
            return Task.CompletedTask;
        }
        public Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken)
        {
            user.UserName = userName;
            return Task.CompletedTask;
        }
        public async Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetUser.Where(AspNetUserFields.Id.Equal(user.Id));

                var userEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                if (userEntity == null)
                {
                    return IdentityResult.Failed(new IdentityError { Description = $"Could not find user to update {user.Id}, {user.Email}." });
                }
                else
                {
                    userEntity.Id = user.Id;
                    userEntity.UserName = user.UserName;
                    userEntity.NormalizedUserName = user.UserName.ToUpper();
                    userEntity.Email = user.Email;
                    userEntity.NormalizedEmail = user.Email.ToUpper();
                    userEntity.EmailConfirmed = user.EmailConfirmed;
                    userEntity.PasswordHash = user.PasswordHash;
                    userEntity.SecurityStamp = user.SecurityStamp;
                    userEntity.ConcurrencyStamp = user.ConcurrencyStamp;
                    userEntity.PhoneNumber = user.PhoneNumber;
                    userEntity.PhoneNumberConfirmed = user.PhoneNumberConfirmed;
                    userEntity.TwoFactorEnabled = user.TwoFactorEnabled;
                    userEntity.LockoutEnd = user.LockoutEnd;
                    userEntity.LockoutEnabled = user.LockoutEnabled;
                    userEntity.AccessFailedCount = user.AccessFailedCount;

                    bool updated = await adapter.SaveEntityAsync(userEntity, cancellationToken);

                    if (!updated)
                    {
                        return IdentityResult.Failed(new IdentityError { Description = $"Could not update user {user.Id}, {user.Email}." });
                    }
                }
            }

            return IdentityResult.Success;
        }
    }
}
