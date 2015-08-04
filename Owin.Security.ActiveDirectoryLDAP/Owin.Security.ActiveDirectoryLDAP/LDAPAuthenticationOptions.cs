// Per the Apache License, Section 4b, this file has been modified from its original version for use in this library.
// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Web.Helpers;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public class LDAPAuthenticationOptions : AuthenticationOptions
    {
        //TODO: Include/exclude lists for claims?
        public LDAPAuthenticationOptions()
            : base(LDAPAuthenticationDefaults.AuthenticationType)
        {
            AntiForgeryCookieName = AntiForgeryConfig.CookieName;
            AntiForgeryFieldName = LDAPAuthenticationDefaults.AntiForgeryFieldName;
            AuthenticationMode = AuthenticationMode.Active;
            CallbackPath = new PathString("/signin-activedirectoryldap");
            Caption = LDAPAuthenticationDefaults.Caption;
            ClaimTypes = new List<string>();//defaults?
            DomainKey = LDAPAuthenticationDefaults.DomainKey;
            //Domains = new List<DomainCredential>();
            PasswordKey = LDAPAuthenticationDefaults.PasswordKey;
            ReturnUrlParameter = LDAPAuthenticationDefaults.ReturnUrlParameter;
            StateKey = LDAPAuthenticationDefaults.StateKey;
            UsernameKey = LDAPAuthenticationDefaults.UsernameKey;
            ValidateAntiForgeryToken = true;

            RequiredClaims = new ReadOnlyCollection<string>(new List<string>
            {
                AntiForgeryConfig.UniqueClaimTypeIdentifier,
                ClaimsIdentity.DefaultNameClaimType,
                ClaimsIdentity.DefaultRoleClaimType,
                ClaimTypesAD.DisplayName,
                ClaimTypesAD.Domain,
                ClaimTypesAD.Guid,
                System.Security.Claims.ClaimTypes.NameIdentifier,
                System.Security.Claims.ClaimTypes.PrimarySid
            });
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
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }
        /// <summary>
        /// The types of optional claims wanted in the claims identity.
        /// </summary>
        public IList<string> ClaimTypes { get; set; }
        /// <summary>
        /// The form input name of the domain field; used if no domain is included with the username.
        /// </summary>
        public string DomainKey { get; set; }
        ///// <summary>
        ///// A list of active directory domain credentials for LDAP connections.
        ///// </summary>
        //public IList<DomainCredential> Domains { get; set; }
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
        /// <summary>
        /// The path to redirect to for setting the local authentication cookie when being used in passive (external) mode.
        /// </summary>
        public PathString RedirectPath { get; set; }
        /// <summary>
        /// The ReturnUrlParameter determines the name of the query string parameter which is appended by the middleware
        /// to the RedirectPath if local authentication is being performed externally to the middleware.
        /// </summary>
        public string ReturnUrlParameter { get; set; }
        /// <summary>
        /// The serialization format to use in claims.
        /// </summary>
        public SerializationFormat SerializationFormat { get; set; }
        /// <summary>
        /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="System.Security.Claims.ClaimsIdentity"/>.
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
        /// <summary>
        /// A function delegate for deciding if a UserPrincipal is allowed to be authenticated.
        /// </summary>
        public Func<UserPrincipal, bool> ValidUser { get; set; } //TODO: Should we be allowing this at all, or leave it entirely to AD?
        /// <summary>
        /// Claims that are required in the claims identity for normal operation.
        /// </summary>
        public IReadOnlyCollection<string> RequiredClaims { get; private set; }

        internal PrincipalContext GetContext(string domain)
        {
            var credentials = Owin.Security.ActiveDirectoryLDAP.TEST.DomainCredentials.Where(_ => !String.IsNullOrEmpty(_.NetBIOS)).FirstOrDefault(_ => _.NetBIOS.Equals(domain, StringComparison.OrdinalIgnoreCase));
            if (credentials == null)
                return null;
            return credentials.GetContext();
        }
    }
}
