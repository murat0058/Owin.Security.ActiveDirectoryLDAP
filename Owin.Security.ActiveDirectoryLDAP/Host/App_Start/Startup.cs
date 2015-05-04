using System;
using System.Collections.Generic;
using Microsoft.Owin;
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
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = LDAPAuthenticationDefaults.AuthenticationType,//Why is this needed? Can we get this to go through the external cookie pipeline instead? should we?
                //Why does this break cookies? I'm pretty sure it has something to do with hijacking AuthenticationType
                //CookieName = "derp",
                //CookiePath = "/home",
                Provider = new CookieAuthenticationProvider
                {
                    OnValidateIdentity = LDAPAuthenticationProvider.OnValidateIdentity(TimeSpan.FromMinutes(1))//15mins
                }
            });

            app.UseLDAPAuthentication(new LDAPAuthenticationOptions
            {
                Domains = MvcApplication.DomainCredentials,
                LoginPath = new PathString("/Home/Login"),
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

            //app.UseLDAPAuthentication(new LDAPAuthenticationOptions
            //{
            //    Domains = MvcApplication.DomainCredentials,
            //    LoginPath = new PathString("/Home/Login"),
            //    //Provider =
            //});
        }
    }
}