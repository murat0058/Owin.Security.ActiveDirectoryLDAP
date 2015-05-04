using System;
using System.Data.Common;
using System.DirectoryServices.AccountManagement;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public class DomainCredential
    {
        //TODO: Custom config section?
        public DomainCredential(string name, string connectionString)
        {
            //TODO: Custom parser?
            var builder = new DbConnectionStringBuilder();
            builder.ConnectionString = connectionString;

            object value;
            if (builder.TryGetValue("Container", out value))
                Container = value as string;
            if (builder.TryGetValue("Domain", out value))
                Domain = value as string;
            if (builder.TryGetValue("Password", out value))
                Password = value as string;
            if (builder.TryGetValue("SecureConnection", out value))
                SecureConnection = bool.Parse(value as string ?? "False");
            if (builder.TryGetValue("Username", out value))
                Username = value as string;
        }

        public DomainCredential(string name, string domain, string container = null, string username = null, string password = null, bool secureConnection = false)
        {
            Container = container;
            Domain = domain;
            Name = name;
            Password = password;
            SecureConnection = secureConnection;
            Username = username;
        }

        //TODO: Handle switchoff between SecureConnection and Domain with a given port, which takes prescedence? throw when trying to set missmatch?
        public string Container { get; set; }
        public string Domain { get; set; }//Strip port number/change SecureConnection based on it?
        public string Name { get; set; }
        public string Password { get; set; }
        public bool SecureConnection { get; set; }
        public string Username { get; set; }

        internal ContextOptions ContextOptions
        {
            get
            {
                return SecureConnection ? ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer : ContextOptions.SimpleBind;
            }
        }

        internal PrincipalContext GetContext()
        {
            return new PrincipalContext(ContextType.Domain, Domain, Container ?? String.Empty, ContextOptions, Username, Password);
        }
    }
}
