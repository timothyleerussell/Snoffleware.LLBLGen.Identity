﻿//////////////////////////////////////////////////////////////
// <auto-generated>This code was generated by LLBLGen Pro v5.9.</auto-generated>
//////////////////////////////////////////////////////////////
// Code is generated on: 
// Code is generated using templates: SD.TemplateBindings.SharedTemplates
// Templates vendor: Solutions Design.
//////////////////////////////////////////////////////////////
using System;
using Snoffleware.LLBLGen.Identity.Core.Data.FactoryClasses;
using Snoffleware.LLBLGen.Identity.Core.Data.RelationClasses;
using SD.LLBLGen.Pro.ORMSupportClasses;

namespace Snoffleware.LLBLGen.Identity.Core.Data.HelperClasses
{
	/// <summary>Singleton implementation of the ModelInfoProvider. This class is the singleton wrapper through which the actual instance is retrieved.</summary>
	public static class ModelInfoProviderSingleton
	{
		private static readonly IModelInfoProvider _providerInstance = new ModelInfoProviderCore();

		/// <summary>Dummy static constructor to make sure threadsafe initialization is performed.</summary>
		static ModelInfoProviderSingleton()	{ }

		/// <summary>Gets the singleton instance of the ModelInfoProviderCore</summary>
		/// <returns>Instance of the FieldInfoProvider.</returns>
		public static IModelInfoProvider GetInstance()
		{
			return _providerInstance;
		}
	}

	/// <summary>Actual implementation of the ModelInfoProvider.</summary>
	internal class ModelInfoProviderCore : ModelInfoProviderBase
	{
		/// <summary>Initializes a new instance of the <see cref="ModelInfoProviderCore"/> class.</summary>
		internal ModelInfoProviderCore()
		{
			Init();
		}

		/// <summary>Method which initializes the internal datastores.</summary>
		private void Init()
		{
			this.InitClass();
			InitAspNetRoleEntityInfo();
			InitAspNetRoleClaimEntityInfo();
			InitAspNetUserEntityInfo();
			InitAspNetUserClaimEntityInfo();
			InitAspNetUserLoginEntityInfo();
			InitAspNetUserRoleEntityInfo();
			InitAspNetUserTokenEntityInfo();
			this.BuildInternalStructures();
		}

		/// <summary>Inits AspNetRoleEntity's info objects</summary>
		private void InitAspNetRoleEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(AspNetRoleFieldIndex), "AspNetRoleEntity");
			this.AddElementFieldInfo("AspNetRoleEntity", "ConcurrencyStamp", typeof(System.String), false, false, false, true,  (int)AspNetRoleFieldIndex.ConcurrencyStamp, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetRoleEntity", "Id", typeof(System.String), true, false, false, false,  (int)AspNetRoleFieldIndex.Id, 450, 0, 0);
			this.AddElementFieldInfo("AspNetRoleEntity", "Name", typeof(System.String), false, false, false, true,  (int)AspNetRoleFieldIndex.Name, 256, 0, 0);
			this.AddElementFieldInfo("AspNetRoleEntity", "NormalizedName", typeof(System.String), false, false, false, true,  (int)AspNetRoleFieldIndex.NormalizedName, 256, 0, 0);
		}

		/// <summary>Inits AspNetRoleClaimEntity's info objects</summary>
		private void InitAspNetRoleClaimEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(AspNetRoleClaimFieldIndex), "AspNetRoleClaimEntity");
			this.AddElementFieldInfo("AspNetRoleClaimEntity", "ClaimType", typeof(System.String), false, false, false, true,  (int)AspNetRoleClaimFieldIndex.ClaimType, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetRoleClaimEntity", "ClaimValue", typeof(System.String), false, false, false, true,  (int)AspNetRoleClaimFieldIndex.ClaimValue, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetRoleClaimEntity", "Id", typeof(System.Int32), true, false, true, false,  (int)AspNetRoleClaimFieldIndex.Id, 0, 0, 10);
			this.AddElementFieldInfo("AspNetRoleClaimEntity", "RoleId", typeof(System.String), false, true, false, false,  (int)AspNetRoleClaimFieldIndex.RoleId, 450, 0, 0);
		}

		/// <summary>Inits AspNetUserEntity's info objects</summary>
		private void InitAspNetUserEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(AspNetUserFieldIndex), "AspNetUserEntity");
			this.AddElementFieldInfo("AspNetUserEntity", "AccessFailedCount", typeof(System.Int32), false, false, false, false,  (int)AspNetUserFieldIndex.AccessFailedCount, 0, 0, 10);
			this.AddElementFieldInfo("AspNetUserEntity", "ConcurrencyStamp", typeof(System.String), false, false, false, true,  (int)AspNetUserFieldIndex.ConcurrencyStamp, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "Email", typeof(System.String), false, false, false, true,  (int)AspNetUserFieldIndex.Email, 256, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "EmailConfirmed", typeof(System.Boolean), false, false, false, false,  (int)AspNetUserFieldIndex.EmailConfirmed, 0, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "Id", typeof(System.String), true, false, false, false,  (int)AspNetUserFieldIndex.Id, 450, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "LockoutEnabled", typeof(System.Boolean), false, false, false, false,  (int)AspNetUserFieldIndex.LockoutEnabled, 0, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "LockoutEnd", typeof(Nullable<System.DateTimeOffset>), false, false, false, true,  (int)AspNetUserFieldIndex.LockoutEnd, 0, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "NormalizedEmail", typeof(System.String), false, false, false, true,  (int)AspNetUserFieldIndex.NormalizedEmail, 256, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "NormalizedUserName", typeof(System.String), false, false, false, true,  (int)AspNetUserFieldIndex.NormalizedUserName, 256, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "PasswordHash", typeof(System.String), false, false, false, true,  (int)AspNetUserFieldIndex.PasswordHash, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "PhoneNumber", typeof(System.String), false, false, false, true,  (int)AspNetUserFieldIndex.PhoneNumber, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "PhoneNumberConfirmed", typeof(System.Boolean), false, false, false, false,  (int)AspNetUserFieldIndex.PhoneNumberConfirmed, 0, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "ProfileImage", typeof(System.String), false, false, false, true,  (int)AspNetUserFieldIndex.ProfileImage, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "SecurityStamp", typeof(System.String), false, false, false, true,  (int)AspNetUserFieldIndex.SecurityStamp, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "TwoFactorEnabled", typeof(System.Boolean), false, false, false, false,  (int)AspNetUserFieldIndex.TwoFactorEnabled, 0, 0, 0);
			this.AddElementFieldInfo("AspNetUserEntity", "UserName", typeof(System.String), false, false, false, true,  (int)AspNetUserFieldIndex.UserName, 256, 0, 0);
		}

		/// <summary>Inits AspNetUserClaimEntity's info objects</summary>
		private void InitAspNetUserClaimEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(AspNetUserClaimFieldIndex), "AspNetUserClaimEntity");
			this.AddElementFieldInfo("AspNetUserClaimEntity", "ClaimType", typeof(System.String), false, false, false, true,  (int)AspNetUserClaimFieldIndex.ClaimType, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetUserClaimEntity", "ClaimValue", typeof(System.String), false, false, false, true,  (int)AspNetUserClaimFieldIndex.ClaimValue, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetUserClaimEntity", "Id", typeof(System.Int32), true, false, true, false,  (int)AspNetUserClaimFieldIndex.Id, 0, 0, 10);
			this.AddElementFieldInfo("AspNetUserClaimEntity", "UserId", typeof(System.String), false, true, false, false,  (int)AspNetUserClaimFieldIndex.UserId, 450, 0, 0);
		}

		/// <summary>Inits AspNetUserLoginEntity's info objects</summary>
		private void InitAspNetUserLoginEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(AspNetUserLoginFieldIndex), "AspNetUserLoginEntity");
			this.AddElementFieldInfo("AspNetUserLoginEntity", "LoginProvider", typeof(System.String), true, false, false, false,  (int)AspNetUserLoginFieldIndex.LoginProvider, 128, 0, 0);
			this.AddElementFieldInfo("AspNetUserLoginEntity", "ProviderDisplayName", typeof(System.String), false, false, false, true,  (int)AspNetUserLoginFieldIndex.ProviderDisplayName, 2147483647, 0, 0);
			this.AddElementFieldInfo("AspNetUserLoginEntity", "ProviderKey", typeof(System.String), true, false, false, false,  (int)AspNetUserLoginFieldIndex.ProviderKey, 128, 0, 0);
			this.AddElementFieldInfo("AspNetUserLoginEntity", "UserId", typeof(System.String), false, true, false, false,  (int)AspNetUserLoginFieldIndex.UserId, 450, 0, 0);
		}

		/// <summary>Inits AspNetUserRoleEntity's info objects</summary>
		private void InitAspNetUserRoleEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(AspNetUserRoleFieldIndex), "AspNetUserRoleEntity");
			this.AddElementFieldInfo("AspNetUserRoleEntity", "RoleId", typeof(System.String), true, true, false, false,  (int)AspNetUserRoleFieldIndex.RoleId, 450, 0, 0);
			this.AddElementFieldInfo("AspNetUserRoleEntity", "UserId", typeof(System.String), true, true, false, false,  (int)AspNetUserRoleFieldIndex.UserId, 450, 0, 0);
		}

		/// <summary>Inits AspNetUserTokenEntity's info objects</summary>
		private void InitAspNetUserTokenEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(AspNetUserTokenFieldIndex), "AspNetUserTokenEntity");
			this.AddElementFieldInfo("AspNetUserTokenEntity", "LoginProvider", typeof(System.String), true, false, false, false,  (int)AspNetUserTokenFieldIndex.LoginProvider, 128, 0, 0);
			this.AddElementFieldInfo("AspNetUserTokenEntity", "Name", typeof(System.String), true, false, false, false,  (int)AspNetUserTokenFieldIndex.Name, 128, 0, 0);
			this.AddElementFieldInfo("AspNetUserTokenEntity", "UserId", typeof(System.String), true, true, false, false,  (int)AspNetUserTokenFieldIndex.UserId, 450, 0, 0);
			this.AddElementFieldInfo("AspNetUserTokenEntity", "Value", typeof(System.String), false, false, false, true,  (int)AspNetUserTokenFieldIndex.Value, 2147483647, 0, 0);
		}
	}
}