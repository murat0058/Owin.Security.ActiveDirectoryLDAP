using System;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;

namespace Host.Controllers
{
    public class AccountController : Controller
    {
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null || loginInfo.ExternalIdentity == null || !loginInfo.ExternalIdentity.IsAuthenticated)
            {
                if (Url.IsLocalUrl(returnUrl))
                    return Redirect(returnUrl);//Put them through the loop again.
                return RedirectToAction("Login");//Can we carry over the state somehow instead?
            }

            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            AuthenticationManager.SignIn(new ClaimsIdentity(loginInfo.ExternalIdentity.Claims, DefaultAuthenticationTypes.ApplicationCookie));
            return Redirect(Url.IsLocalUrl(returnUrl) ? returnUrl : "/");
        }

        public ActionResult Login()
        {
            return View();
        }
    }
}