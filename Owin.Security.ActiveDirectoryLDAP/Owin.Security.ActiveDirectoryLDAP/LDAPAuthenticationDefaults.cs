using System;

namespace Owin.Security.ActiveDirectoryLDAP
{
    /// <summary>
    /// Default values related to LDAP authentication middleware
    /// </summary>
    public static class LDAPAuthenticationDefaults
    {
        internal const string AntiForgeryFieldName = "__RequestVerificationToken";//For some ridiculous reason they define this in an internal class so we need to hard code it here. (System.Web.Helpers.AntiXsrf.AntiForgeryConfigWrapper)

        /// <summary>
        /// The default value used for LDAPAuthenticationOptions.AuthenticationType
        /// </summary>
        public const string AuthenticationType = "ActiveDirectoryLDAP";

        /// <summary>
        /// The prefix used to provide a default LDAPAuthenticationOptions.CookiePrefix
        /// </summary>
        public const string CookiePrefix = "LDAP.";//unused

        /// <summary>
        /// The prefix used to provide a default LDAPAuthenticationOptions.CookieName
        /// </summary>
        public const string CookieName = "LDAPAuth";//unused

        /// <summary>
        /// The default value for LDAPAuthenticationOptions.Caption.
        /// </summary>
        public const string Caption = "Active Directory LDAP";

        /// <summary>
        /// The default form input name for the account component of the user login credentials.
        /// </summary>
        public const string UsernameKey = "Username";

        /// <summary>
        /// The default form input name for the password component of the user login credentials.
        /// </summary>
        public const string PasswordKey = "Password";

        /// <summary>
        /// The default form input name for the domain component of the user login credentials, used if one is not included as part of the username.
        /// </summary>
        public const string DomainKey = "Domain";

        /// <summary>
        /// The default form input name for the OWIN state data.
        /// </summary>
        public const string StateKey = "State";//OwinState?
    }
}
