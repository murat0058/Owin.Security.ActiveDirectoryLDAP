using System;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public static class LDAPAuthenticationExtensions
    {
        public static IAppBuilder UseLDAPAuthentication(this IAppBuilder app, LDAPAuthenticationOptions options)
        {
            return app.Use(typeof(LDAPAuthenticationMiddleware), app, options);
        }
    }
}
