using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.ActiveDirectoryLDAP
{
    // One instance is created when the application starts.
    public class LDAPAuthenticationMiddleware : AuthenticationMiddleware<LDAPAuthenticationOptions>
    {
        public LDAPAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, LDAPAuthenticationOptions options)
            : base(next, options)
        {
            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }
            if (options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(LDAPAuthenticationMiddleware).FullName,
                    options.AuthenticationType);

                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
        }

        public override Task Invoke(IOwinContext context)
        {
            return base.Invoke(context);
        }

        // Called for each request, to create a handler for each request.
        protected override AuthenticationHandler<LDAPAuthenticationOptions> CreateHandler()
        {
            return new LDAPAuthenticationHandler();
        }
    }
}
