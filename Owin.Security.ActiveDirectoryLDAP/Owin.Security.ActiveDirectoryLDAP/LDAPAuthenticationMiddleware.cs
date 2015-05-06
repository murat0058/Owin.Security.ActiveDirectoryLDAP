// Per the Apache License, Section 4b, this file has been modified from its original version for use in this library.
// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.
using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public class LDAPAuthenticationMiddleware : AuthenticationMiddleware<LDAPAuthenticationOptions>
    {
        public LDAPAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, LDAPAuthenticationOptions options)
            : base(next, options)
        {
            //if (string.IsNullOrWhiteSpace(Options.ConsumerSecret))
            //{
            //    throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ConsumerSecret"));
            //}
            //if (string.IsNullOrWhiteSpace(Options.ConsumerKey))
            //{
            //    throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ConsumerKey"));
            //}

            if (options.Provider == null)
            {
                options.Provider = new LDAPAuthenticationProvider();
            }
            if (options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(LDAPAuthenticationMiddleware).FullName,
                    options.AuthenticationType);

                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }
        }

        public override Task Invoke(IOwinContext context)
        {
            return base.Invoke(context);
        }

        protected override AuthenticationHandler<LDAPAuthenticationOptions> CreateHandler()
        {
            return new LDAPAuthenticationHandler();
        }
    }
}
