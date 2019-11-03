using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Snoffleware.LLBLGen.Identity.Core.Data.DatabaseSpecific;
using Snoffleware.LLBLGen.Identity.Core.Data.EntityClasses;
using Snoffleware.LLBLGen.Identity.Core.Models;
using SD.LLBLGen.Pro.QuerySpec;
using SD.LLBLGen.Pro.QuerySpec.Adapter;
using Snoffleware.LLBLGen.Identity.Core.Data.HelperClasses;
using Snoffleware.LLBLGen.Identity.Core.Data.FactoryClasses;
using System.Security.Claims;
using Snoffleware.LLBLGen.Identity.Core.Data.Linq;

namespace Snoffleware.LLBLGen.Identity.Core
{
    public class RoleStore :
        IQueryableRoleStore<ApplicationRole>,
        IRoleClaimStore<ApplicationRole>,
        IRoleStore<ApplicationRole>
    {
        IQueryable<ApplicationRole> IQueryableRoleStore<ApplicationRole>.Roles
        {
            get
            {
                DataAccessAdapter adapter = new DataAccessAdapter();
                try
                {
                    var md = new LinqMetaData(adapter);
                    var q = from roleEntity in md.AspNetRole
                            select new ApplicationRole()
                            {
                                Id = roleEntity.Id,
                                Name = roleEntity.Name,
                                NormalizedName = roleEntity.NormalizedName,
                                ConcurrencyStamp = roleEntity.ConcurrencyStamp
                            };
                    return q;
                }
                finally
                {
                    adapter.CloseConnection();
                }
            }
        }
        public async Task AddClaimAsync(ApplicationRole role, Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetRole.Where(AspNetRoleFields.NormalizedName.Equal(role.NormalizedName));

                var fetchedRole = await adapter.FetchFirstAsync(q, cancellationToken);

                if (fetchedRole != null)
                {
                    AspNetRoleClaimEntity roleClaimEntity = new AspNetRoleClaimEntity();
                    roleClaimEntity.RoleId = role.Id;
                    roleClaimEntity.ClaimType = claim.Type;
                    roleClaimEntity.ClaimValue = claim.Value;

                    await adapter.SaveEntityAsync(roleClaimEntity, cancellationToken);
                }
            }
        }
        public async Task<IdentityResult> CreateAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                AspNetRoleEntity roleEntity = new AspNetRoleEntity();
                roleEntity.Id = role.Id;
                roleEntity.Name = role.Name;
                roleEntity.NormalizedName = role.Name.ToUpper();
                roleEntity.ConcurrencyStamp = role.ConcurrencyStamp;

                bool saved = await adapter.SaveEntityAsync(roleEntity, cancellationToken);
                if (!saved)
                {
                    return IdentityResult.Failed(new IdentityError { Description = $"Could not insert role {role.Name}." });
                }
            }

            return IdentityResult.Success;
        }
        public async Task<IdentityResult> DeleteAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var roleToDelete = new AspNetRoleEntity(role.Id);
                bool deleted = await adapter.DeleteEntityAsync(roleToDelete, cancellationToken);

                if (!deleted)
                {
                    return IdentityResult.Failed(new IdentityError { Description = $"Could not delete role {role.Name}." });
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
            if(disposing)
            {
                //free managed resources
            }
        }
        public async Task<ApplicationRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetRole.Where(AspNetRoleFields.Id.Equal(roleId));

                var roleEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                if (roleEntity != null)
                {
                    ApplicationRole role = new ApplicationRole();
                    role.Id = roleEntity.Id;
                    role.Name = roleEntity.Name;
                    role.NormalizedName = roleEntity.NormalizedName;
                    role.ConcurrencyStamp = roleEntity.ConcurrencyStamp;
                    return role;
                }

                return null;
            }
        }
        public async Task<ApplicationRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetRole.Where(AspNetRoleFields.NormalizedName.Equal(normalizedRoleName));

                var roleEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                if(roleEntity != null)
                {
                    ApplicationRole role = new ApplicationRole();
                    role.Id = roleEntity.Id;
                    role.Name = roleEntity.Name;
                    role.NormalizedName = roleEntity.NormalizedName;
                    role.ConcurrencyStamp = roleEntity.ConcurrencyStamp;
                    return role;
                }

                return null;
            }
        }
        public async Task<IList<Claim>> GetClaimsAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetRoleClaim.Where(AspNetRoleClaimFields.RoleId.Equal(role.Id));

                var roleClaims = await adapter.FetchQueryAsync(q, cancellationToken);

                return roleClaims.Cast<AspNetRoleClaimEntity>().Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
            }
        }
        public Task<string> GetNormalizedRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(role.NormalizedName);
        }
        public Task<string> GetRoleIdAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(role.Id);
        }
        public Task<string> GetRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(role.Name);
        }
        public async Task RemoveClaimAsync(ApplicationRole role, Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetRoleClaim.Where(AspNetRoleClaimFields.RoleId.Equal(role.Id)
                    .And(AspNetRoleClaimFields.ClaimValue.Equal(claim.Value))
                    .And(AspNetRoleClaimFields.ClaimType.Equal(claim.Type)));

                var roleClaimEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                if (roleClaimEntity != null)
                {
                    roleClaimEntity.RoleId = role.Id;
                    roleClaimEntity.ClaimType = claim.Type;
                    roleClaimEntity.ClaimValue = claim.Value;

                    await adapter.SaveEntityAsync(roleClaimEntity, cancellationToken);
                }
            }
        }
        public Task SetNormalizedRoleNameAsync(ApplicationRole role, string normalizedName, CancellationToken cancellationToken)
        {
            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }
        public Task SetRoleNameAsync(ApplicationRole role, string roleName, CancellationToken cancellationToken)
        {
            role.Name = roleName;
            return Task.CompletedTask;
        }
        public async Task<IdentityResult> UpdateAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var adapter = new DataAccessAdapter())
            {
                var qf = new QueryFactory();
                var q = qf.AspNetRole.Where(AspNetRoleFields.Id.Equal(role.Id));

                var roleEntity = await adapter.FetchFirstAsync(q, cancellationToken);

                if (roleEntity == null)
                {
                    return IdentityResult.Failed(new IdentityError { Description = $"Could not find role to update {role.Name}." });
                }
                else
                {
                    //roleEntity.Id = role.Id; //probably should not be able to modify and persist the id, can't find in available docs, db constraint _should_ let you know.
                    roleEntity.Name = role.Name;
                    roleEntity.NormalizedName = role.Name.ToUpper();
                    roleEntity.ConcurrencyStamp = role.ConcurrencyStamp;

                    bool updated = await adapter.SaveEntityAsync(roleEntity, cancellationToken);

                    if (!updated)
                    {
                        return IdentityResult.Failed(new IdentityError { Description = $"Could not update role {role.Name}." });
                    }
                }
            }

            return IdentityResult.Success;
        }
    }
}
