using System;
using System.Security.Claims;

namespace Owin.Security.ActiveDirectoryLDAP
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1052:StaticHolderTypesShouldBeSealed", Justification = "This isn't a static class, it is only meant to eventually have a static constructor.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1053:StaticHolderTypesShouldNotHaveConstructors", Justification = "This isn't a static class, it is only meant to eventually have a static constructor.")]
    public class User
    {
        private User()
        {
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA1801:ReviewUnusedParameters", MessageId = "identity", Justification = "This can be removed once implemented.")]
        public static User FromClaimsIdentity(ClaimsIdentity identity)
        {
            throw new NotImplementedException();
        }
    }
}