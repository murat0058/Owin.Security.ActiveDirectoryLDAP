// Per the Apache License, Section 4b, this file has been modified from its original version for use in this library.
// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Web.Helpers;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public class LDAPAuthenticationOptions : AuthenticationOptions
    {
        //TODO: More/better constructors, securestring password? should we bother?
        public LDAPAuthenticationOptions()
            : base(LDAPAuthenticationDefaults.AuthenticationType)
        {
            AntiForgeryCookieName = AntiForgeryConfig.CookieName;
            AntiForgeryFieldName = LDAPAuthenticationDefaults.AntiForgeryFieldName;
            AuthenticationMode = AuthenticationMode.Active;
            CallbackPath = new PathString("/signin-ldap");
            DefaultReturnPath = new PathString("/");
            Description.Caption = LDAPAuthenticationDefaults.Caption;
            DomainKey = LDAPAuthenticationDefaults.DomainKey;
            Domains = new List<DomainCredential>();
            PasswordKey = LDAPAuthenticationDefaults.PasswordKey;
            Provider = new LDAPAuthenticationProvider();
            SignInAsAuthenticationType = LDAPAuthenticationDefaults.AuthenticationType;//Should this be here?
            StateKey = LDAPAuthenticationDefaults.StateKey;//required
            UsernameKey = LDAPAuthenticationDefaults.UsernameKey;
            UseStateCookie = true;
            ValidateAntiForgeryToken = true;
        }

        /// <summary>
        /// The name of the cookie containing the antiforgery token value.
        /// </summary>
        public string AntiForgeryCookieName { get; set; }
        /// <summary>
        /// The name of the form input containing the antiforgery token value.
        /// </summary>
        public string AntiForgeryFieldName { get; set; }
        /// <summary>
        /// The path to post back the login information to.
        /// </summary>
        public PathString CallbackPath { get; set; }
        /// <summary>
        /// The default path to redirect to after authentication if the authentication state is invalid or missing.
        /// </summary>
        public PathString DefaultReturnPath { get; set; }
        /// <summary>
        /// The form input name of the domain field; used if no domain is included with the username.
        /// </summary>
        public string DomainKey { get; set; }
        /// <summary>
        /// A list of active directory domain credentials for LDAP connections.
        /// </summary>
        public IList<DomainCredential> Domains { get; set; }
        /// <summary>
        /// A function delegate for getting the form token value from somewhere other than the POST body (e.g. headers).
        /// </summary>
        public Func<IOwinRequest, string> GetAntiForgeryToken { get; set; }
        /// <summary>
        /// The path to the login page that posts back to the callback path.
        /// </summary>
        public PathString LoginPath { get; set; }
        /// <summary>
        /// The form input name of the password field.
        /// </summary>
        public string PasswordKey { get; set; }
        /// <summary>
        /// Gets or sets the <see cref="ILDAPAuthenticationProvider"/> used to handle authentication events.
        /// </summary>
        public ILDAPAuthenticationProvider Provider { get; set; }
        ///// <summary>
        ///// The serialization format to use in claims.
        ///// </summary>
        //public SerializationFormat SerializationFormat { get; set; }
        /// <summary>
        ///
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }//What?
        /// <summary>
        /// Gets or sets the <see cref="ISecureDataFormat"/> used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        /// <summary>
        /// The form input/cookie name of the state field.
        /// </summary>
        public string StateKey { get; set; }
        /// <summary>
        /// The form input name of the username field.
        /// </summary>
        public string UsernameKey { get; set; }
        /// <summary>
        /// Whether or not the authentication state should be passed using a cookie or query parameter.
        /// </summary>
        public bool UseStateCookie { get; set; }
        /// <summary>
        /// Whether or not antiforgery tokens should be validated on a login request to the callback path.
        /// </summary>
        public bool ValidateAntiForgeryToken { get; set; }

        internal PrincipalContext GetContext(string domain)
        {
            var credentials = Domains.Where(_ => !String.IsNullOrEmpty(_.Name)).FirstOrDefault(_ => _.Name.Equals(domain, StringComparison.OrdinalIgnoreCase));
            if (credentials == null)
                return null;
            return credentials.GetContext();
        }
    }
}
