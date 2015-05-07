// Per the Apache License, Section 4b, this file has been modified from its original version for use in this library.
// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.
using System;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Helpers;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.ActiveDirectoryLDAP
{
    internal struct ADLogin
    {
        public string Domain { get; set; }
        public string Username { get; set; }

        public static ADLogin Parse(string username)
        {
            username = username ?? String.Empty;
            var old = username.Split(new char[] { '\\' }, 2);//Old domain\user
            var upn = username.Split(new char[] { '@' }, 2);//UPN user@domain

            if (old.Length == 2)
                return new ADLogin { Domain = old[0], Username = old[1] };
            else if (upn.Length == 2)
                return new ADLogin { Domain = old[1], Username = old[0] };
            else
                return new ADLogin { Username = username };
        }
    }

    // Created by the factory in the LDAPAuthenticationMiddleware class.
    internal class LDAPAuthenticationHandler : AuthenticationHandler<LDAPAuthenticationOptions>
    {
        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        //Should only be hit in active mode.
        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401 || !Options.LoginPath.HasValue)
                return;

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge == null)
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
                properties.RedirectUri = currentUri;//TODO: I think this is expecting the extenral auth callback url, not the page url (it depends on what mode it is operating in)
            }

            //properties.Dictionary["ReturnUrl"] = currentUri;

            var authenticationEndpoint = Options.LoginPath.Value;
            if (Options.UseStateCookie)
                Context.Response.Cookies.Append(Options.StateKey, Options.StateDataFormat.Protect(properties), new CookieOptions { HttpOnly = true, Secure = Request.IsSecure });
            else
                authenticationEndpoint = WebUtilities.AddQueryString(authenticationEndpoint, Options.StateKey, Options.StateDataFormat.Protect(properties));

            var redirectContext = new LDAPApplyRedirectContext(Context, Options, properties, authenticationEndpoint);
            Options.Provider.ApplyRedirect(redirectContext);
        }

        protected override Task ApplyResponseCoreAsync()
        {
            return base.ApplyResponseCoreAsync();
        }

        protected override Task ApplyResponseGrantAsync()
        {
            return base.ApplyResponseGrantAsync();
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            //Redirect back to login if fail beyond this point?

            if (String.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
                && !String.IsNullOrWhiteSpace(Request.ContentType)
                // May have media/type; charset=utf-8, allow partial match.
                && (Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
                    || Request.ContentType.StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase))
                && Request.Body.CanRead)
            {
                //Handle JSON post data?
                //&& Request.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase)//json post? ajax?

                if (!Request.Body.CanSeek)
                {
                    // Buffer in case this body was not meant for us.
                    var memoryStream = new MemoryStream();
                    await Request.Body.CopyToAsync(memoryStream);
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    Request.Body = memoryStream;
                }
                var form = await Request.ReadFormAsync();
                Request.Body.Seek(0, SeekOrigin.Begin);

                if (!Options.ValidateAntiForgeryToken || ValidAntiForgeryTokens(form))
                {
                    //LDAP domain is case insensitive
                    var login = ADLogin.Parse(form.Get(Options.UsernameKey));
                    var username = login.Username;
                    var password = form.Get(Options.PasswordKey);
                    var domain = login.Domain ?? form.Get(Options.DomainKey);

                    var state = Options.UseStateCookie
                        ? Request.Cookies[Options.StateKey]//Check form/query if not present?
                        : form.Get(Options.StateKey) ?? Request.Query[Options.StateKey];//TODO: Check referer header as last ditch?

                    ClaimsIdentity identity;
                    if (TryValidateCredentials(domain, username, password, out identity))//TODO: Pass back proper error reason
                    {
                        var context = new LDAPAuthenticatedContext(Context, null, null, null, null);
                        context.Identity = identity;
                        context.Properties = Options.StateDataFormat.Unprotect(state);

                        await Options.Provider.Authenticated(context);

                        return new AuthenticationTicket(context.Identity, context.Properties);
                    }
                }
            }

            return null;
        }

        protected override Task InitializeCoreAsync()
        {
            return base.InitializeCoreAsync();
        }

        protected override Task TeardownCoreAsync()
        {
            return base.TeardownCoreAsync();
        }

        #region Private Methods

        private async Task<bool> InvokeReturnPathAsync()
        {
            var model = await AuthenticateAsync();//Calls AuthenticateCoreAsync()
            if (model == null)
            {
                //TODO: Construct proper redirect back to login page if we failed, also need to handle ajax responses or have some handler so a user can do it as well.
                //e.g. await Options.Provider.ReturnEndpoint(context);
                Response.Redirect(WebUtilities.AddQueryString(Options.LoginPath.Value, "error", "access_denied"));
                return false;//This kills our process, we need to redirect back.
                //Response.StatusCode = 500;
                //return true;
            }

            var context = new LDAPReturnEndpointContext(Context, model);
            context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
            context.RedirectUri = model.Properties.RedirectUri;
            //model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                if (Options.UseStateCookie && Request.Cookies[Options.StateKey] != null)
                    Response.Cookies.Delete(Options.StateKey, new CookieOptions { HttpOnly = true, Secure = Request.IsSecure });
                
                var signInIdentity = context.Identity;
                //TODO: If ExternalCallbackPath doesn't have a value, should we be setting the actual session cookie?
                if (!String.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (!context.IsRequestCompleted)// && context.RedirectUri != null)
            {
                //Add a provider event handle here to catch the redirect in case we want to do AJAX post back?
                context.RedirectUri = Options.RedirectPath.HasValue
                                    ? Options.RedirectPath.Value
                                    : String.IsNullOrEmpty(context.RedirectUri)//TODO: this RedirectUri is _supposed_ to be the ExternalCallbackPath I think, not the page redirect url.
                                    ? "/"
                                    : context.RedirectUri;//TODO: Try to get Redirect path from form if there isn't one in the properties?

                //if (context.Identity == null)
                //{
                //    // add a redirect hint that sign-in failed in some way
                //    context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                //}
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }


            //if (!context.IsRequestCompleted && context.RedirectUri != null)
            //{
            //    if (context.Identity == null)
            //    {
            //        // add a redirect hint that sign-in failed in some way
            //        context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
            //    }
            //    Response.Redirect(context.RedirectUri);
            //    context.RequestCompleted();
            //}

            return context.IsRequestCompleted;
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
                        identity = user.GetClaimsIdentity(Options.AuthenticationType, domain, issuer: "AD AUTHORITY", serializationFormat: Options.SerializationFormat);
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

        private bool ValidAntiForgeryTokens(IFormCollection form)
        {
            //Use the existing cookie if there is one. There may still end up being two (different paths), but this will reduce that chance.
            //Would we want to delete our own pathed cookie if there is one further up?

            var cookieToken = Request.Cookies[Options.AntiForgeryCookieName];
            var methodToken = Options.GetAntiForgeryToken != null
                            ? Options.GetAntiForgeryToken(Request)
                            : form.Get(Options.AntiForgeryFieldName);

            if (String.IsNullOrEmpty(cookieToken) ||
                String.IsNullOrEmpty(methodToken))
                return false;

            try
            {
                AntiForgery.Validate(cookieToken, methodToken);
                return true;
            }
            catch (Exception)//System.Web.Helpers.HttpAntiForgeryException
            {
                return false;
            }
        }

        #endregion Private Methods
    }
}
