using System;
using System.Security.Claims;
using System.Web.Mvc;
using Security.ClaimAttributes.Mvc;

namespace Host.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            var user = User.Identity as ClaimsIdentity;

            return View();
        }

        [GroupAuthorize(Name = "Test1")]
        [GroupAuthorize(Sid = "S-1-5-15")]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}