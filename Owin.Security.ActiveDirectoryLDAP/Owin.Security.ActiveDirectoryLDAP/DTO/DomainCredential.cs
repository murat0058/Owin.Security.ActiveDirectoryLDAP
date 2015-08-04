using System;
using System.Collections.Generic;
using System.Data.Common;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public static class TEST
    {
        private static IList<DomainCredential> s_DomainCredentials { get; set; }
        public static IList<DomainCredential> DomainCredentials
        {
            get
            {
                if (s_DomainCredentials == null)
                {
                    s_DomainCredentials = new List<DomainCredential>();
                    foreach (System.Configuration.ConnectionStringSettings connection in System.Configuration.ConfigurationManager.ConnectionStrings)
                    {
                        if (connection.ProviderName == "ActiveDirectoryLDAP")
                            s_DomainCredentials.Add(new DomainCredential(connection.ConnectionString));
                    }
                }
                return s_DomainCredentials;
            }
        }
    }

    public class DomainCredential
    {
        //TODO: Custom config section?
        //TODO: Combine constructors
        public DomainCredential(string connectionString)
        {
            //TODO: Custom parser?
            var builder = new DbConnectionStringBuilder();
            builder.ConnectionString = connectionString;

            object[] value = new object[6];
            builder.TryGetValue("NetBIOS", out value[0]);
            builder.TryGetValue("Domain", out value[1]);
            builder.TryGetValue("Container", out value[2]);
            builder.TryGetValue("Username", out value[3]);
            builder.TryGetValue("Password", out value[4]);
            builder.TryGetValue("SecureConnection", out value[5]);

            if (String.IsNullOrWhiteSpace(value[0] as string))
                throw new ArgumentNullException("netbios");
            if (String.IsNullOrWhiteSpace(value[1] as string))
                throw new ArgumentNullException("domain");
            if (String.IsNullOrWhiteSpace(value[2] as string))
                throw new ArgumentNullException("container");

            NetBIOS = value[0] as string;
            Domain = value[1] as string;
            Container = value[2] as string;
            Username = value[3] as string;
            Password = value[4] as string;
            SecureConnection = bool.Parse(value[5] as string ?? "False");
        }

        public DomainCredential(string netbios, string domain, string container, string username = null, string password = null, bool secureConnection = false)
        {
            if (String.IsNullOrWhiteSpace(netbios))
                throw new ArgumentNullException("netbios");
            if (String.IsNullOrWhiteSpace(domain))
                throw new ArgumentNullException("domain");
            if (String.IsNullOrWhiteSpace(container))
                throw new ArgumentNullException("container");

            Container = container;
            Domain = domain;
            NetBIOS = netbios;
            Password = password;
            SecureConnection = secureConnection;
            Username = username;
        }

        public string Container { get; set; }
        public string Domain { get; set; }//Strip port number/change SecureConnection based on it?
        public string NetBIOS { get; set; }
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
            return new PrincipalContext(ContextType.Domain, Domain, Container, ContextOptions, Username, Password);
        }
    }
}
