using System;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.ActiveDirectoryLDAP;

[assembly: OwinStartupAttribute(typeof(Host.Startup))]

namespace Host
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            //app.SetDefaultSignInAsAuthenticationType(DefaultAuthenticationTypes.ApplicationCookie);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                CookieName = "Session",
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                //LoginPath = new PathString("/Home/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    OnValidateIdentity = LDAPAuthenticationProvider.OnValidateIdentity(TimeSpan.FromMinutes(1))//15mins
                }
            });

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseLDAPAuthentication(new LDAPAuthenticationOptions
            {
                Domains = MvcApplication.DomainCredentials,
                LoginPath = new PathString("/Home/Login"),
                //AuthenticationMode = AuthenticationMode.Passive,
                ExternalCallbackPath = new PathString("/Account/ExternalLoginCallback"),
                //Provider =
            });

            //app.SetDefaultSignInAsAuthenticationType(LDAPAuthenticationDefaults.AuthenticationType);

            //app.UseCookieAuthentication(new CookieAuthenticationOptions
            //{
            //    //AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
            //    AuthenticationType = LDAPAuthenticationDefaults.AuthenticationType,
            //    //LoginPath = new PathString("/Home/Login"),
            //    //Provider = new CookieAuthenticationProvider
            //    //{
            //    //    //OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
            //    //    //    validateInterval: TimeSpan.FromMinutes(30),
            //    //    //    regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
            //    //}
            //    Provider = new CookieAuthenticationProvider
            //    {
            //        OnValidateIdentity = Custom.OnValidateIdentity(TimeSpan.FromMinutes(1))
            //    }
            //});
        }
    }
}