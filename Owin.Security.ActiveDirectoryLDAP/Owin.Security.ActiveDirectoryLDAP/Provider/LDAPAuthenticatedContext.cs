// Per the Apache License, Section 4b, this file has been modified from its original version for use in this library.
// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.ActiveDirectoryLDAP
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class LDAPAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="LDAPAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="userId">LDAP user ID</param>
        /// <param name="screenName">LDAP screen name</param>
        /// <param name="accessToken">LDAP access token</param>
        /// <param name="accessTokenSecret">LDAP access token secret</param>
        public LDAPAuthenticatedContext(
            IOwinContext context,
            string userId,
            string screenName,
            string accessToken,
            string accessTokenSecret)
            : base(context)
        {
            UserId = userId;
            ScreenName = screenName;
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;
        }

        /// <summary>
        /// Gets the LDAP user ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the LDAP screen name
        /// </summary>
        public string ScreenName { get; private set; }

        /// <summary>
        /// Gets the LDAP access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the LDAP access token secret
        /// </summary>
        public string AccessTokenSecret { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}
