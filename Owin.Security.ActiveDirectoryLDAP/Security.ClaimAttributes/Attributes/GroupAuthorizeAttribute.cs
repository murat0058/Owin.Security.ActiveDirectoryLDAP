using System;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Http.Controllers;
using http = System.Web.Http;
using mvc = System.Web.Mvc;

namespace Security.ClaimAttributes.Mvc
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = true, AllowMultiple = true)]
    public class GroupAuthorizeAttribute : mvc.AuthorizeAttribute
    {
        public string Name { get; set; }
        public string Sid { get; set; }

        public GroupAuthorizeAttribute()
        {
            //if (String.IsNullOrEmpty(Name) && String.IsNullOrEmpty(Sid))
            //    throw new ArgumentException("A Name or Sid must be specified.");
        }

        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            if (httpContext == null)
            {
                throw new ArgumentNullException("httpContext");
            }

            var user = httpContext.User as ClaimsPrincipal;
            if (user == null || user.Identity == null || !user.Identity.IsAuthenticated)
            {
                return false;
            }

            if (String.IsNullOrEmpty(Sid))
            {
                var config = Configuration.GroupConfiguration.Groups.FirstOrDefault(_ => _.Name.Equals(Name, StringComparison.Ordinal));
                if (config != null)
                    Sid = config.Sid;
            }

            if (!user.HasClaim(ClaimTypes.GroupSid, Sid))
            {
                return false;
            }

            return true;
        }
    }
}

namespace Security.ClaimAttributes.Http
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = true, AllowMultiple = true)]
    public class GroupAuthorizeAttribute : http.AuthorizeAttribute
    {
        public string GroupName { get; set; }
        public string GroupSid { get; set; }

        public GroupAuthorizeAttribute()
        {
            //if (String.IsNullOrEmpty(GroupName) && String.IsNullOrEmpty(GroupSid))
            //    throw new ArgumentException("A Name or Sid must be specified.");
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

            if (String.IsNullOrEmpty(GroupSid))
            {
                var config = Configuration.GroupConfiguration.Groups.FirstOrDefault(_ => _.Name.Equals(GroupName, StringComparison.Ordinal));
                if (config != null)
                    GroupSid = config.Sid;
            }

            if (!user.HasClaim(ClaimTypes.GroupSid, GroupSid))
            {
                return false;
            }

            return true;
        }
    }
}