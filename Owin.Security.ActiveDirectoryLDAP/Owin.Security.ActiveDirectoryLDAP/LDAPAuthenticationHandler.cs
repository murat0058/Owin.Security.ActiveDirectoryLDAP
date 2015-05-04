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
        ////protected virtual Task ApplyResponseChallengeAsync();
        //protected virtual Task ApplyResponseCoreAsync();
        //protected virtual Task ApplyResponseGrantAsync();
        ////protected abstract Task<AuthenticationTicket> AuthenticateCoreAsync();
        //protected virtual Task InitializeCoreAsync();
        /////public virtual Task<bool> InvokeAsync();
        //protected virtual Task TeardownCoreAsync();

        //// Summary:
        ////     Override this method to deal with 401 challenge concerns, if an authentication
        ////     scheme in question deals an authentication interaction as part of it's request
        ////     flow. (like adding a response header, or changing the 401 result to 302 of
        ////     a login page or external sign-in location.)
        //protected virtual Task ApplyResponseChallengeAsync();
        ////
        //// Summary:
        ////     Core method that may be overridden by handler. The default behavior is to
        ////     call two common response activities, one that deals with sign-in/sign-out
        ////     concerns, and a second to deal with 401 challenges.
        //[DebuggerStepThrough]
        //protected virtual Task ApplyResponseCoreAsync();
        ////
        //// Summary:
        ////     Override this method to dela with sign-in/sign-out concerns, if an authentication
        ////     scheme in question deals with grant/revoke as part of it's request flow.
        ////     (like setting/deleting cookies)
        //protected virtual Task ApplyResponseGrantAsync();
        ////
        //// Summary:
        ////     The core authentication logic which must be provided by the handler. Will
        ////     be invoked at most once per request. Do not call directly, call the wrapping
        ////     Authenticate method instead.
        ////
        //// Returns:
        ////     The ticket data provided by the authentication logic
        //protected abstract Task<AuthenticationTicket> AuthenticateCoreAsync();
        ////
        //// Summary:
        ////     Called once by common code after initialization. If an authentication middleware
        ////     responds directly to specifically known paths it must override this virtual,
        ////     compare the request path to it's known paths, provide any response information
        ////     as appropriate, and true to stop further processing.
        ////
        //// Returns:
        ////     Returning false will cause the common code to call the next middleware in
        ////     line. Returning true will cause the common code to begin the async completion
        ////     journey without calling the rest of the middleware pipeline.
        //public virtual Task<bool> InvokeAsync();

        protected override Task InitializeCoreAsync()
        {
            return base.InitializeCoreAsync();
        }

        public override async Task<bool> InvokeAsync()
        {
            //D this earlier?
            //if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)

            var ticket = await AuthenticateAsync();//Calls AuthenticateCoreAsync()
            if (ticket == null)
            {
                return false;
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
                if (Options.UseStateCookie && Request.Cookies[Options.StateKey] != null)
                    Response.Cookies.Delete(Options.StateKey, new CookieOptions { HttpOnly = true, Secure = Request.IsSecure });
                Request.Context.Authentication.SignIn(ticket.Properties, ticket.Identity);//Should we be doing this if there is no redirect?
            }

            //Add a provider event handle here to catch the redirect in case we want to do AJAX post back?

            // Redirect back to the original secured resource, if any.
            if (!String.IsNullOrWhiteSpace(ticket.Properties.RedirectUri))
            {
                Response.Redirect(ticket.Properties.RedirectUri);
                return true;
            }
            else if (Options.DefaultReturnPath.HasValue)
            {
                Response.Redirect(Options.DefaultReturnPath.Value);
                return true;
            }
            //else broken

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
            if (Options.CallbackPath.HasValue && Options.CallbackPath != (Request.PathBase + Request.Path))
                return null;

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
                    var state = form.Get(Options.StateKey) ?? Request.Query[Options.StateKey] ?? Request.Cookies[Options.StateKey];//TODO: Check referer header as last ditch?
                    //Check the UseStateCookie option instead of trying all possible locations?

                    ClaimsIdentity identity;
                    if (TryValidateCredentials(domain, username, password, out identity))
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
