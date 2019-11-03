using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Text;

namespace Snoffleware.LLBLGen.Identity.Test
{
    public static class ConfigurationUtility
    {
        private static IConfigurationRoot configurationRoot;
        public static IConfigurationRoot GetIConfigurationRoot()
        {
            //Each developer needs to replace this with their own secret store id to run the tests
            //The guid can be found in the .csproj file after running dotnet user-secrets init 
            //https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets?view=aspnetcore-3.0&tabs=windows

            var builder = new ConfigurationBuilder()
                .AddUserSecrets("6447caa4-5462-4f05-aac7-92430512a54f");

            configurationRoot = builder.Build();

            return configurationRoot;
        }

        public static string GetSecret(string name)
        {
            string appSettings = configurationRoot[name];
            return appSettings;
        }
    }
}
