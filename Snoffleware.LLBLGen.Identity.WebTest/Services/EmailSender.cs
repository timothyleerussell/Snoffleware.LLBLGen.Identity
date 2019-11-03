using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Snoffleware.LLBLGen.Identity.WebTest.Services
{
    public class EmailSender : IEmailSender
    {
        public EmailSender(IOptions<AuthMessageSenderOptions> optionsAccessor)
        {
            Options = optionsAccessor.Value;
        }

        public AuthMessageSenderOptions Options { get; }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            //TODO: currently an email sink, mimimum required implementation
            //we'll throw something out for diagnostics
            Debug.WriteLine("Sending email...");
            Debug.WriteLine("Email address: " + email ?? "No email address specified.");
            Debug.WriteLine("Subject: " + subject ?? "No subject specified.");

            string message = String.IsNullOrWhiteSpace(htmlMessage) ? "No message." : htmlMessage;
            string truncatedMessage = (htmlMessage.Length >= 256) ? htmlMessage.Substring(0, 256) : htmlMessage;

            Debug.WriteLine("Message: " + truncatedMessage);

            return Task.CompletedTask;
        }
    }
}
