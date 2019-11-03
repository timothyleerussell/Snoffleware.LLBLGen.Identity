# Snoffleware.LLBLGen.Identity

A .NET Core 3.0 Identity custom UserStore/RoleStore implementation using LLBLGen (https://llblgen.com) as the persistence provider.

Author: Timothy Lee Russell / Snoffleware Studios LLC / https://snoffleware.com

License: MIT

---

## What is it and who is it for?

If you use LLBLGen and .NET Core 3.0 and want to add the Microsoft identity tables to a new or existing database to provide authentication and authorization leveraging the built-in .NET Core security machinations while also having a unified interface to your data including the Identity tables using LLBLGen, this is the project for you.

## Tests

I could not find much information about testing a custom UserStore but I felt that tests were important for something so crucial as a security-related piece. A best effort attempt has been made to write effective tests and to make it relatively easy to write new tests against the stores, allowing code coverage to expand as needed.

Nothing is mocked, we are testing the plumbing so we are reading and writing directly to a test database.

Tests should pack out all their trash.

## Security implications

We're not overriding any of the .net core 3.0 identity functionality other than the User/Role stores. We simply want to change the persistence provider. As long as we're storing and retrieving the values correctly, which the tests attempt to validate, we're safely leveraging the default .net core security infrastructure but with LLBLGen as the ORM.

That *should* mean access to all of the built-in authorization attributes, such as Authorize, Authorize(Roles) and Authorize(Policies).

This lets us add .net core identity authentication and authorization to a legacy database easily and move it to Azure. Your use case may vary.

Would love to have someone at Microsoft do a code review!

## WebTest site details

The `WebTest` project features the 3.0 version of the scaffolded mvc identity area.

There are a couple changes in this project from the default scaffolding:

- Removed IdentityHostingStartup EF code
- Modified ~/Areas/Identity/Pages/Account/Manage/EnableAuthenticator.cshtml to include a QR code using `qrcodejs` per the example in Microsoft docs
- HomeController Privacy method set to [Authorize]

The goal is to take a database we want to move to Azure and easily add authentication and authorization by simply running a sql script to add the identity membership tables and create a unified model, with all of the tables accessible using the LLBLGen framework of your choice but with user vetting performed by the .net core identity system.

More tests will be added as issues are found and further examples of authorization will be added to the WebTest project in a future release. If anyone from the LLBLGen community finds this useful and wants to help make this project better, that would be great. If you just want to use it, that's ok too!

### Thanks

Special thanks to Frans Bouma (https://twitter.com/FransBouma) for reviewing the code.

Any mistakes are my own but the code benefited greatly from his solid advice.

Code reviews by domain experts are so valuable. Don't be afraid to ask for help!

## Steps to setup the project

1. Create a blank database

2. Run sql in the file: `Microsoft-Identity-Tables-From-Scaffolding-net-core-2.2.txt`

3. Set secret connection string for the `Test` AND `WebTest` projects with your `data source` and `initial catalog` values. Repeat the command in each directory.

	To set the secret, open a Powershell prompt inside each project directory and run the `dotnet user-secrets set` command. Following the security practice of keeping secrets outside of your code can help to prevent credential leaks.	   
	`
	PS> dotnet user-secrets set "ConnectionString.SQL Server (SqlClient)" "data source=YOURCOMPUTER\SQLINSTANCE;initial catalog=Snoffleware-LLBLGen-Identity-   Dev;integrated security=SSPI;persist security info=False"
	`
4. Change the UserSecrets guid in the `Test` project -> `ConfigurationUtility` class.
	This guid needs to match up with your user secrets store. You can find this guid after you setup user secrets by editing the `Test` project's `.csproj` file.
	Recompile to solidify this change.

5. The web project seems to know about the user secrets automatically. Only the `Test` project requires a special treatment because all of the code has to be manually constructed.

6. ~~OR you can swap in hard-coded connection string values in those two projects~~ The user secrets method is strongly suggested as this prevents you from checking in secrets, in a fork of the project, for example.

7. At this point, you should be able to run the `Test` and `WebTest` projects. You can register a user, login and view the protected Privacy page. You can also click on the profile link and edit the user using the default Microsoft UI. App-based 2FA (TOTP) is hooked up with QR codes provided by `qrcodejs`.

8. Email is only stubbed. Currently the email output writes to the debug console. If you want to test email confirmation / forgot password functionality with an actual email service, you can implement that in `WebTest->Services->EmailSender.cs`

