﻿//////////////////////////////////////////////////////////////
// <auto-generated>This code was generated by LLBLGen Pro 5.9.</auto-generated>
//////////////////////////////////////////////////////////////
// Code is generated on: 
// Code is generated using templates: SD.TemplateBindings.SharedTemplates
// Templates vendor: Solutions Design.
//////////////////////////////////////////////////////////////
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Xml.Serialization;
using Snoffleware.LLBLGen.Identity.Core.Data.HelperClasses;
using Snoffleware.LLBLGen.Identity.Core.Data.FactoryClasses;
using Snoffleware.LLBLGen.Identity.Core.Data.RelationClasses;

using SD.LLBLGen.Pro.ORMSupportClasses;

namespace Snoffleware.LLBLGen.Identity.Core.Data.EntityClasses
{
	// __LLBLGENPRO_USER_CODE_REGION_START AdditionalNamespaces
	// __LLBLGENPRO_USER_CODE_REGION_END
	/// <summary>Entity class which represents the entity 'AspNetUserToken'.<br/><br/></summary>
	[Serializable]
	public partial class AspNetUserTokenEntity : CommonEntityBase
		// __LLBLGENPRO_USER_CODE_REGION_START AdditionalInterfaces
		// __LLBLGENPRO_USER_CODE_REGION_END	
	{
		private AspNetUserEntity _aspNetUser;

		// __LLBLGENPRO_USER_CODE_REGION_START PrivateMembers
		// __LLBLGENPRO_USER_CODE_REGION_END
		private static AspNetUserTokenEntityStaticMetaData _staticMetaData = new AspNetUserTokenEntityStaticMetaData();
		private static AspNetUserTokenRelations _relationsFactory = new AspNetUserTokenRelations();

		/// <summary>All names of fields mapped onto a relation. Usable for in-memory filtering</summary>
		public static partial class MemberNames
		{
			/// <summary>Member name AspNetUser</summary>
			public static readonly string AspNetUser = "AspNetUser";
		}

		/// <summary>Static meta-data storage for navigator related information</summary>
		protected class AspNetUserTokenEntityStaticMetaData : EntityStaticMetaDataBase
		{
			public AspNetUserTokenEntityStaticMetaData()
			{
				SetEntityCoreInfo("AspNetUserTokenEntity", InheritanceHierarchyType.None, false, (int)Snoffleware.LLBLGen.Identity.Core.Data.EntityType.AspNetUserTokenEntity, typeof(AspNetUserTokenEntity), typeof(AspNetUserTokenEntityFactory), false);
				AddNavigatorMetaData<AspNetUserTokenEntity, AspNetUserEntity>("AspNetUser", "AspNetUserTokens", (a, b) => a._aspNetUser = b, a => a._aspNetUser, (a, b) => a.AspNetUser = b, Snoffleware.LLBLGen.Identity.Core.Data.RelationClasses.StaticAspNetUserTokenRelations.AspNetUserEntityUsingUserIdStatic, ()=>new AspNetUserTokenRelations().AspNetUserEntityUsingUserId, null, new int[] { (int)AspNetUserTokenFieldIndex.UserId }, null, true, (int)Snoffleware.LLBLGen.Identity.Core.Data.EntityType.AspNetUserEntity);
			}
		}

		/// <summary>Static ctor</summary>
		static AspNetUserTokenEntity()
		{
		}

		/// <summary> CTor</summary>
		public AspNetUserTokenEntity()
		{
			InitClassEmpty(null, null);
		}

		/// <summary> CTor</summary>
		/// <param name="fields">Fields object to set as the fields for this entity.</param>
		public AspNetUserTokenEntity(IEntityFields2 fields)
		{
			InitClassEmpty(null, fields);
		}

		/// <summary> CTor</summary>
		/// <param name="validator">The custom validator object for this AspNetUserTokenEntity</param>
		public AspNetUserTokenEntity(IValidator validator)
		{
			InitClassEmpty(validator, null);
		}

		/// <summary> CTor</summary>
		/// <param name="loginProvider">PK value for AspNetUserToken which data should be fetched into this AspNetUserToken object</param>
		/// <param name="name">PK value for AspNetUserToken which data should be fetched into this AspNetUserToken object</param>
		/// <param name="userId">PK value for AspNetUserToken which data should be fetched into this AspNetUserToken object</param>
		public AspNetUserTokenEntity(System.String loginProvider, System.String name, System.String userId) : this(loginProvider, name, userId, null)
		{
		}

		/// <summary> CTor</summary>
		/// <param name="loginProvider">PK value for AspNetUserToken which data should be fetched into this AspNetUserToken object</param>
		/// <param name="name">PK value for AspNetUserToken which data should be fetched into this AspNetUserToken object</param>
		/// <param name="userId">PK value for AspNetUserToken which data should be fetched into this AspNetUserToken object</param>
		/// <param name="validator">The custom validator object for this AspNetUserTokenEntity</param>
		public AspNetUserTokenEntity(System.String loginProvider, System.String name, System.String userId, IValidator validator)
		{
			InitClassEmpty(validator, null);
			this.LoginProvider = loginProvider;
			this.Name = name;
			this.UserId = userId;
		}

		/// <summary>Private CTor for deserialization</summary>
		/// <param name="info"></param>
		/// <param name="context"></param>
		protected AspNetUserTokenEntity(SerializationInfo info, StreamingContext context) : base(info, context)
		{
			// __LLBLGENPRO_USER_CODE_REGION_START DeserializationConstructor
			// __LLBLGENPRO_USER_CODE_REGION_END
		}

		/// <summary>Creates a new IRelationPredicateBucket object which contains the predicate expression and relation collection to fetch the related entity of type 'AspNetUser' to this entity.</summary>
		/// <returns></returns>
		public virtual IRelationPredicateBucket GetRelationInfoAspNetUser() { return CreateRelationInfoForNavigator("AspNetUser"); }
		
		/// <inheritdoc/>
		protected override EntityStaticMetaDataBase GetEntityStaticMetaData() {	return _staticMetaData; }

		/// <summary>Initializes the class members</summary>
		private void InitClassMembers()
		{
			PerformDependencyInjection();
			// __LLBLGENPRO_USER_CODE_REGION_START InitClassMembers
			// __LLBLGENPRO_USER_CODE_REGION_END
			OnInitClassMembersComplete();
		}

		/// <summary>Initializes the class with empty data, as if it is a new Entity.</summary>
		/// <param name="validator">The validator object for this AspNetUserTokenEntity</param>
		/// <param name="fields">Fields of this entity</param>
		private void InitClassEmpty(IValidator validator, IEntityFields2 fields)
		{
			OnInitializing();
			this.Fields = fields ?? CreateFields();
			this.Validator = validator;
			InitClassMembers();
			// __LLBLGENPRO_USER_CODE_REGION_START InitClassEmpty
			// __LLBLGENPRO_USER_CODE_REGION_END

			OnInitialized();
		}

		/// <summary>The relations object holding all relations of this entity with other entity classes.</summary>
		public static AspNetUserTokenRelations Relations { get { return _relationsFactory; } }

		/// <summary>Creates a new PrefetchPathElement2 object which contains all the information to prefetch the related entities of type 'AspNetUser' for this entity.</summary>
		/// <returns>Ready to use IPrefetchPathElement2 implementation.</returns>
		public static IPrefetchPathElement2 PrefetchPathAspNetUser { get { return _staticMetaData.GetPrefetchPathElement("AspNetUser", CommonEntityBase.CreateEntityCollection<AspNetUserEntity>()); } }

		/// <summary>The LoginProvider property of the Entity AspNetUserToken<br/><br/></summary>
		/// <remarks>Mapped on  table field: "AspNetUserTokens"."LoginProvider".<br/>Table field type characteristics (type, precision, scale, length): NVarChar, 0, 0, 128.<br/>Table field behavior characteristics (is nullable, is PK, is identity): false, true, false</remarks>
		public virtual System.String LoginProvider
		{
			get { return (System.String)GetValue((int)AspNetUserTokenFieldIndex.LoginProvider, true); }
			set	{ SetValue((int)AspNetUserTokenFieldIndex.LoginProvider, value); }
		}

		/// <summary>The Name property of the Entity AspNetUserToken<br/><br/></summary>
		/// <remarks>Mapped on  table field: "AspNetUserTokens"."Name".<br/>Table field type characteristics (type, precision, scale, length): NVarChar, 0, 0, 128.<br/>Table field behavior characteristics (is nullable, is PK, is identity): false, true, false</remarks>
		public virtual System.String Name
		{
			get { return (System.String)GetValue((int)AspNetUserTokenFieldIndex.Name, true); }
			set	{ SetValue((int)AspNetUserTokenFieldIndex.Name, value); }
		}

		/// <summary>The UserId property of the Entity AspNetUserToken<br/><br/></summary>
		/// <remarks>Mapped on  table field: "AspNetUserTokens"."UserId".<br/>Table field type characteristics (type, precision, scale, length): NVarChar, 0, 0, 450.<br/>Table field behavior characteristics (is nullable, is PK, is identity): false, true, false</remarks>
		public virtual System.String UserId
		{
			get { return (System.String)GetValue((int)AspNetUserTokenFieldIndex.UserId, true); }
			set	{ SetValue((int)AspNetUserTokenFieldIndex.UserId, value); }
		}

		/// <summary>The Value property of the Entity AspNetUserToken<br/><br/></summary>
		/// <remarks>Mapped on  table field: "AspNetUserTokens"."Value".<br/>Table field type characteristics (type, precision, scale, length): NVarChar, 0, 0, 2147483647.<br/>Table field behavior characteristics (is nullable, is PK, is identity): true, false, false</remarks>
		public virtual System.String Value
		{
			get { return (System.String)GetValue((int)AspNetUserTokenFieldIndex.Value, true); }
			set	{ SetValue((int)AspNetUserTokenFieldIndex.Value, value); }
		}

		/// <summary>Gets / sets related entity of type 'AspNetUserEntity' which has to be set using a fetch action earlier. If no related entity is set for this property, null is returned..<br/><br/></summary>
		[Browsable(false)]
		public virtual AspNetUserEntity AspNetUser
		{
			get { return _aspNetUser; }
			set { SetSingleRelatedEntityNavigator(value, "AspNetUser"); }
		}

		// __LLBLGENPRO_USER_CODE_REGION_START CustomEntityCode
		// __LLBLGENPRO_USER_CODE_REGION_END

	}
}

namespace Snoffleware.LLBLGen.Identity.Core.Data
{
	public enum AspNetUserTokenFieldIndex
	{
		///<summary>LoginProvider. </summary>
		LoginProvider,
		///<summary>Name. </summary>
		Name,
		///<summary>UserId. </summary>
		UserId,
		///<summary>Value. </summary>
		Value,
		/// <summary></summary>
		AmountOfFields
	}
}

namespace Snoffleware.LLBLGen.Identity.Core.Data.RelationClasses
{
	/// <summary>Implements the relations factory for the entity: AspNetUserToken. </summary>
	public partial class AspNetUserTokenRelations: RelationFactory
	{

		/// <summary>Returns a new IEntityRelation object, between AspNetUserTokenEntity and AspNetUserEntity over the m:1 relation they have, using the relation between the fields: AspNetUserToken.UserId - AspNetUser.Id</summary>
		public virtual IEntityRelation AspNetUserEntityUsingUserId
		{
			get	{ return ModelInfoProviderSingleton.GetInstance().CreateRelation(RelationType.ManyToOne, "AspNetUser", false, new[] { AspNetUserFields.Id, AspNetUserTokenFields.UserId }); }
		}

	}
	
	/// <summary>Static class which is used for providing relationship instances which are re-used internally for syncing</summary>
	internal static class StaticAspNetUserTokenRelations
	{
		internal static readonly IEntityRelation AspNetUserEntityUsingUserIdStatic = new AspNetUserTokenRelations().AspNetUserEntityUsingUserId;

		/// <summary>CTor</summary>
		static StaticAspNetUserTokenRelations() { }
	}
}
