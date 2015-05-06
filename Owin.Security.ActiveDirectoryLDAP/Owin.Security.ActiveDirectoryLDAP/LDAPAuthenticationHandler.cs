// Per the Apache License, Section 4b, this file has been modified from its original version for use in this library.
// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.
using System;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Helpers;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.ActiveDirectoryLDAP
{
    // Created by the factory in the LDAPAuthenticationMiddleware class.
    internal class LDAPAuthenticationHandler : AuthenticationHandler<LDAPAuthenticationOptions>
    {
        protected override Task InitializeCoreAsync()
        {
            return base.InitializeCoreAsync();
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                var ticket = await AuthenticateAsync();//Calls AuthenticateCoreAsync()
                if (ticket == null)
                {
                    //TODO: Construct proper redirect back to login page if we failed, also need to handle ajax responses or have some handler so a user can do it as well.
                    //e.g. await Options.Provider.ReturnEndpoint(context);
                    Response.Redirect(WebUtilities.AddQueryString(Options.LoginPath.Value, "error", "access_denied"));

                    return false;//This kills our process, we need to redirect back.
                }

                //var context = new TwitterReturnEndpointContext(Context, model)
                //{
                //    SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                //    RedirectUri = model.Properties.RedirectUri
                //};
                //await Options.Provider.ReturnEndpoint(context);

                //string value;
                //if (ticket.Properties.Dictionary.TryGetValue(HandledResponse, out value) && value == "true")
                //{
                //    return true;
                //}
                if (ticket.Identity != null)
                {
                    var properties = ticket.Properties;
                    if (Options.UseStateCookie && Request.Cookies[Options.StateKey] != null)
                        Response.Cookies.Delete(Options.StateKey, new CookieOptions { HttpOnly = true, Secure = Request.IsSecure });

                    //Add a provider event handle here to catch the redirect in case we want to do AJAX post back?
                    if (Options.ExternalCallbackPath.HasValue)
                    {
                        Request.Context.Authentication.SignIn(properties, ticket.Identity);
                        Response.Redirect(Options.ExternalCallbackPath.Value);
                        return true;
                    }
                    else
                    {
                        Request.Context.Authentication.SignIn(new ClaimsIdentity(ticket.Identity.Claims, Options.SignInAsAuthenticationType));//properties?
                        Response.Redirect(String.IsNullOrEmpty(properties.RedirectUri) ? "/" : properties.RedirectUri);//TODO: Try to get Redirect path from form if there isn't one in the properties?
                        return true;
                    }
                }
            }

            return false;
            //return base.InvokeAsync();
        }

        protected override Task ApplyResponseCoreAsync()
        {
            return base.ApplyResponseCoreAsync();
        }

        protected override Task ApplyResponseGrantAsync()
        {
            return base.ApplyResponseGrantAsync();
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)// || !Options.LoginPath.HasValue)
                return;

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge == null)//Is challenge ever not null here?
                return;

            var baseUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                Request.Host +
                Request.PathBase;

            var currentUri =
                baseUri +
                Request.Path +
                Request.QueryString;

            // Save the original challenge URI so we can redirect back to it when we're done.
            var properties = challenge.Properties;
            if (String.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            var authenticationEndpoint = WebUtilities.AddQueryString(Options.LoginPath.Value, Options.StateKey, Options.StateDataFormat.Protect(properties));

            if (Options.UseStateCookie)
            {
                Context.Response.Cookies.Append(Options.StateKey, Options.StateDataFormat.Protect(properties), new CookieOptions { HttpOnly = true, Secure = Request.IsSecure });
                var redirectContext = new LDAPApplyRedirectContext(Context, Options, properties, authenticationEndpoint);
                //Options.Provider.ApplyRedirect(redirectContext);
                Response.Redirect(Options.LoginPath.Value);//???
            }
            else
            {
                var redirectContext = new LDAPApplyRedirectContext(Context, Options, properties, authenticationEndpoint);
                //Options.Provider.ApplyRedirect(redirectContext);
                Response.Redirect(WebUtilities.AddQueryString(Options.LoginPath.Value, Options.StateKey, Options.StateDataFormat.Protect(properties)));//???
            }
        }

        //called on every request
        protected override Task TeardownCoreAsync()
        {
            return base.TeardownCoreAsync();
        }

        //Implemented by Microsoft.Owin.Security.WsFederation
        //protected override async Task ApplyResponseGrantAsync()
        //protected override async Task ApplyResponseChallengeAsync()
        //public override Task<bool> InvokeAsync()
        //protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()

        #region Private Methods

        private static bool ValidAntiForgeryTokens(string cookieToken, string formToken)
        {
            if (String.IsNullOrEmpty(cookieToken) ||
                String.IsNullOrEmpty(formToken))
                return false;

            try
            {
                AntiForgery.Validate(cookieToken, formToken);
                return true;
            }
            catch (Exception)//System.Web.Helpers.HttpAntiForgeryException
            {
                return false;
            }
        }

        private bool ValidAntiForgeryTokens(IFormCollection form)
        {
            //Use the existing cookie if there is one. There may still end up being two (different paths), but this will reduce that chance.
            //Would we want to delete our own pathed cookie if there is one further up?

            var cookieToken = Request.Cookies[Options.AntiForgeryCookieName];
            var methodToken = Options.GetAntiForgeryToken != null
                            ? Options.GetAntiForgeryToken(Request)
                            : form.Get(Options.AntiForgeryFieldName);
            return ValidAntiForgeryTokens(cookieToken, methodToken);
        }

        private bool TryValidateCredentials(string domain, string username, string password, out ClaimsIdentity identity)
        {
            identity = null;
            if (String.IsNullOrEmpty(username) ||
                String.IsNullOrEmpty(password))
                return false;

            try
            {
                //Create the context with the users credentials or with "application" credentials?
                using (var context = Options.GetContext(domain))
                {
                    var account = domain + "\\" + username;
                    if (context == null || !context.ValidateCredentials(account, password, context.Options))
                        return false;

                    //Lookup and statically store security group name/sid/etc at owin startup time (or with a method)?
                    //If we use an attribute to determine the group(s) a controller method uses, then it would require a code change (and thus restart), so it should work fine.
                    //Or would it be better to cache groups as they are found by the user?
                    //using (var group = new GroupPrincipal(context) { IsSecurityGroup = true })
                    //using (var search = new PrincipalSearcher(group))
                    //{
                    //    var test = search.FindAll();
                    //}

                    using (var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, account))//On refresh lookup by Sid?/Guid IdentityType.Guid
                    {
                        //claim issuer? "AD AUTHORITY"? context.ConnectedServer?
                        identity = user.GetClaimsIdentity(Options.SignInAsAuthenticationType, issuer: "AD AUTHORITY");//Is this the proper "Type"? or should it be Options.AuthenticationType (SignInAsAuthenticationType)
                        return true;
                    }
                }
            }
            catch (PrincipalServerDownException ex)
            {
                Debug.WriteLine(ex);//We should emit the fact that this happened someplace. raise an event to something?
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }
            return false;
        }

        #endregion Private Methods

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            //Redirect back to login if fail beyond this point?

            if (String.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase) && Request.Body.CanRead)
            {
                // May have media/type; charset=utf-8, allow partial match.
                //!String.IsNullOrWhiteSpace(Request.ContentType)
                //Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
                //Request.ContentType.StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase)
                //Request.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase)//json post? ajax?

                //if (!Request.Body.CanSeek)
                //{
                //    _logger.WriteVerbose("Buffering request body");
                //    // Buffer in case this body was not meant for us.
                //    MemoryStream memoryStream = new MemoryStream();
                //    await Request.Body.CopyToAsync(memoryStream);
                //    memoryStream.Seek(0, SeekOrigin.Begin);
                //    Request.Body = memoryStream;
                //}
                //IFormCollection form = await Request.ReadFormAsync();
                //Request.Body.Seek(0, SeekOrigin.Begin);

                var form = await Request.ReadFormAsync();//Will this kill the input stream? It might be needed later.
                if (!Options.ValidateAntiForgeryToken || ValidAntiForgeryTokens(form))
                {
                    //LDAP domain is case insensitive
                    var login = new ADLogin(form.Get(Options.UsernameKey));
                    var username = login.Username;
                    var password = form.Get(Options.PasswordKey);
                    var domain = login.Domain ?? form.Get(Options.DomainKey);

                    var state = Options.UseStateCookie
                        ? Request.Cookies[Options.StateKey]//Check form/query if not present?
                        : form.Get(Options.StateKey) ?? Request.Query[Options.StateKey];//TODO: Check referer header as last ditch?

                    ClaimsIdentity identity;
                    if (TryValidateCredentials(domain, username, password, out identity))//TODO: Pass back proper error reason
                    {
                        //var context = new TwitterAuthenticatedContext(Context, accessToken.UserId, accessToken.ScreenName, accessToken.Token, accessToken.TokenSecret);

                        //context.Identity = new ClaimsIdentity(
                        //    new[]
                        //    {
                        //        new Claim(ClaimTypes.NameIdentifier, accessToken.UserId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        //        new Claim(ClaimTypes.Name, accessToken.ScreenName, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        //        new Claim("urn:twitter:userid", accessToken.UserId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        //        new Claim("urn:twitter:screenname", accessToken.ScreenName, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType)
                        //    },
                        //    Options.AuthenticationType,
                        //    ClaimsIdentity.DefaultNameClaimType,
                        //    ClaimsIdentity.DefaultRoleClaimType);
                        //context.Properties = requestToken.Properties;

                        //await Options.Provider.Authenticated(context);

                        var properties = Options.StateDataFormat.Unprotect(state);
                        return new AuthenticationTicket(identity, properties);
                    }
                }
            }

            return null;
        }
    }

    internal class ADLogin
    {
        public ADLogin(string username)
        {
            username = username ?? String.Empty;
            var old = username.Split(new char[] { '\\' }, 2);//Old domain\user
            var upn = username.Split(new char[] { '@' }, 2);//UPN user@domain

            if (old.Length == 2)
            {
                Domain = old[0];
                Username = old[1];
            }
            else if (upn.Length == 2)
            {
                Domain = old[1];
                Username = old[0];
            }
            else
            {
                Username = username;
            }
        }

        public string Domain { get; set; }
        public string Username { get; set; }
    }
}
