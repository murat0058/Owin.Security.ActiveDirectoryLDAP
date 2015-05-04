using System;
using System.Security.Claims;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public class User
    {
        public static User FromClaimsIdentity(ClaimsIdentity identity)
        {
            throw new NotImplementedException();
        }
    }
}
