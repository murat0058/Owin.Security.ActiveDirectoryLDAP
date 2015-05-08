using System;
using System.Security.Claims;
using System.Web;
using System.Web.Http.Controllers;
using http = System.Web.Http;
using mvc = System.Web.Mvc;

namespace Security.ClaimAttributes.Mvc
{
    public class ClaimAuthorizeAttribute : mvc.AuthorizeAttribute
    {
        private string ClaimType { get; set; }
        private string ClaimValue { get; set; }

        public ClaimAuthorizeAttribute(string type, string value)
        {
            ClaimType = type;
            ClaimValue = value;
        }

        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            if (httpContext == null)
            {
                throw new ArgumentNullException("httpContext");
            }

            var user = httpContext.User as ClaimsPrincipal;
            if (user == null ||user.Identity == null || !user.Identity.IsAuthenticated)
            {
                return false;
            }

            if (!user.HasClaim(ClaimType, ClaimValue))
            {
                return false;
            }

            return true;
        }

        protected override void HandleUnauthorizedRequest(mvc.AuthorizationContext filterContext)
        {
            base.HandleUnauthorizedRequest(filterContext);
        }

        public override void OnAuthorization(mvc.AuthorizationContext filterContext)
        {
            base.OnAuthorization(filterContext);
        }

        protected override HttpValidationStatus OnCacheAuthorization(HttpContextBase httpContext)
        {
            return base.OnCacheAuthorization(httpContext);
        }
    }
}

namespace Security.ClaimAttributes.Http
{
    public class ClaimAuthorizeAttribute : http.AuthorizeAttribute
    {
        private string ClaimType { get; set; }
        private string ClaimValue { get; set; }

        public ClaimAuthorizeAttribute(string type, string value)
        {
            ClaimType = type;
            ClaimValue = value;
        }

        protected override void HandleUnauthorizedRequest(HttpActionContext actionContext)
        {
            base.HandleUnauthorizedRequest(actionContext);
        }

        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            if (actionContext == null)
            {
                throw new ArgumentNullException("actionContext");
            }

            //var user = actionContext.ControllerContext.RequestContext.Principal as ClaimsPrincipal;
            var user = HttpContext.Current.User as ClaimsPrincipal;
            if (user == null || user.Identity == null || !user.Identity.IsAuthenticated)
            {
                return false;
            }

            if (!user.HasClaim(ClaimType, ClaimValue))
            {
                return false;
            }

            return true;
        }

        public override void OnAuthorization(HttpActionContext actionContext)
        {
            base.OnAuthorization(actionContext);
        }
    }
}
