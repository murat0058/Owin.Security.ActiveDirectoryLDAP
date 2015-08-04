// Per the Apache License, Section 4b, this file has been modified from its original version for use in this library.
// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.ActiveDirectoryLDAP
{
    /// <summary>
    /// Default <see cref="ILDAPAuthenticationProvider"/> implementation.
    /// </summary>
    public class LDAPAuthenticationProvider : ILDAPAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="LDAPAuthenticationProvider"/>
        /// </summary>
        public LDAPAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnApplyRedirect = context =>
                context.Response.Redirect(context.RedirectUri);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<LDAPAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<LDAPReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        /// </summary>
        public Action<LDAPApplyRedirectContext> OnApplyRedirect { get; set; }

        /// <summary>
        /// Invoked whenever LDAP succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(LDAPAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(LDAPReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the LDAP middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        public virtual void ApplyRedirect(LDAPApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }

        //Put this someplace else?
        public static Func<CookieValidateIdentityContext, Task> OnValidateIdentity(TimeSpan validateInterval, Func<UserPrincipal, bool> validUser = null, bool checkSid = true)
        {
            return (Func<CookieValidateIdentityContext, Task>)(async cookie =>
            {
                //TODO: Check the auth type of the cookie, we can only refresh our own type here.

                var baseContext = cookie as BaseContext<CookieAuthenticationOptions>;

                // grab the current system time from either the context options clock or the system-wide clock
                var currentUtc = (baseContext != null && baseContext.Options != null && baseContext.Options.SystemClock != null)
                    ? baseContext.Options.SystemClock.UtcNow
                    : DateTimeOffset.UtcNow;

                // get the time we issued this claim-set (and if not there, big-bang)
                var issuedUtc = cookie.Properties.IssuedUtc.GetValueOrDefault(DateTime.MinValue);
                var usedValidityPeriod = currentUtc.Subtract(issuedUtc);
                if (usedValidityPeriod <= validateInterval)// if we've not used up the claim's validity interval we can just return.
                    return;

                // we need to revalidate the claim... need the current user information.
                var identity = cookie.Identity;
                var userGuid = identity.GetGuid();
                if (userGuid == null)//This is an anonymous claim?
                    return;

                // we've got a user, but it may now be invalid...
                identity = await Task.Run(() =>
                {
                    var domain = identity.GetDomain();
                    var credentials = Owin.Security.ActiveDirectoryLDAP.TEST.DomainCredentials.Where(_ => !String.IsNullOrEmpty(_.NetBIOS)).FirstOrDefault(_ => _.NetBIOS.Equals(domain, StringComparison.OrdinalIgnoreCase));
                    if (credentials == null)//No credentials for the users claimed domain, they cannot be revalidated.
                        return default(ClaimsIdentity);

                    try
                    {
                        using (var context = credentials.GetContext())
                        using (var user = UserPrincipal.FindByIdentity(context, IdentityType.Guid, userGuid.ToString()))
                        {
                            if (user != null)
                            {
                                //SecurityStamp? 
                                var isValid = validUser != null
                                            ? validUser(user)
                                            : user.IsValid(checkSid ? identity.GetSid() : null);

                                if (isValid)
                                {
                                    //TODO: This belongs in a claim refresh method on the user
                                    //TODO: _Really_ not sure about this. Update old types with new values, keep old types without new values.
                                    //var oldClaims = identity.Claims.ToList();
                                    //var oldClaimTypes = oldClaims.Select(_ => _.Type).Distinct().ToList();
                                    //var newClaims = user.GetClaims(oldClaimTypes);
                                    //var newClaimTypes = newClaims.Select(_ => _.Type).Distinct().ToList();
                                    //TODO: Not sure we should be carrying over old claims at all.
                                    //foreach (var oldClaim in oldClaims.Where(_ => !newClaimTypes.Contains(_.Type)))
                                    //{
                                    //    newClaims.Add(oldClaim);
                                    //}

                                    var account = domain.ToUpperInvariant() + @"\" + user.SamAccountName.ToLowerInvariant();//TODO: Get domain from user.DistinguishedName instead of using the old one? It probably doesn't matter, I don't think we would be able to re-auth them if they have changed domains (or if it's even possible while keeping the same guid).
                                    var oldClaimTypes = identity.Claims.Select(_ => _.Type).Distinct().ToList();

                                    identity = new ClaimsIdentity(identity.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
                                    identity.AddClaim(new Claim(ClaimTypesAD.Domain, domain, ClaimValueTypes.String));//do we need this?
                                    identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, account));
                                    identity.AddClaims(user.GetClaims(oldClaimTypes));

                                    if (identity != null)
                                    {
                                        baseContext.OwinContext.Authentication.SignIn(identity);
                                        return identity;
                                    }
                                }

                                //// it's a valid user, check the securityStamp to ensure we're using the same "last-login" for this user
                                //var securityStamp = msIdentity.IdentityExtensions.FindFirstValue(identity, ExtraClaimTypes.SecurityStamp);
                                //if (securityStamp != null && securityStamp.Equals(user.SecurityStamp, StringComparison.Ordinal))
                                //{
                                //    identity = RegenerateClaimsIdentity(identity);
                                //    if (identity != null)
                                //    {
                                //        // it's a valid login, and matches everything... issue the identity
                                //        baseContext.OwinContext.Authentication.SignIn(identity);
                                //        return identity;
                                //    }
                                //}

                                //claim issuer? "AD AUTHORITY"? context.ConnectedServer?
                                //identity = user.GetClaimsIdentity(cookie.);//Is this the proper "Type"? or should it be Options.AuthenticationType (SignInAsAuthenticationType)
                                //Get proper type from cookie

                                //TODO: Regenerate identity properly, should replace only the claims that are in the current identity.
                            }
                        }
                    }
                    catch (PrincipalServerDownException ex)
                    {
                        //We should emit the fact that this happened someplace. raise an event to something?
                    }
                    catch (Exception ex)
                    {
                    }

                    return default(ClaimsIdentity);
                });

                if (identity == null)
                {
                    cookie.RejectIdentity();
                    baseContext.OwinContext.Authentication.SignOut(baseContext.Options.AuthenticationType);
                }
            });
        }
    }
}
