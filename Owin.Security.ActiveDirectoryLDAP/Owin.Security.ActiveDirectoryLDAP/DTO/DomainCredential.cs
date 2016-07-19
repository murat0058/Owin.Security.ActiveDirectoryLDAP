using System;
using System.Collections.Generic;
using System.Data.Common;
using System.DirectoryServices.AccountManagement;
using System.Linq;

namespace Owin.Security.ActiveDirectoryLDAP
{
    internal static class DomainCredentialConfig
    {
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

        public static PrincipalContext GetContext(string domain)
        {
            var credentials = DomainCredentials.Where(_ => !String.IsNullOrEmpty(_.NetBIOS)).FirstOrDefault(_ => _.NetBIOS.Equals(domain, StringComparison.OrdinalIgnoreCase));
            if (credentials == null)
                return null;
            return credentials.GetContext();
        }

        private static IList<DomainCredential> s_DomainCredentials { get; set; }
    }

    public class DomainCredential
    {
        //TODO: Custom config section?
        //TODO: Combine constructors
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2208:InstantiateArgumentExceptionsCorrectly", Justification = "The arguments come from the connection string; probably needs a better exception but I'm not sure what to use.")]
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
                throw new ArgumentNullException("NetBIOS");
            if (String.IsNullOrWhiteSpace(value[1] as string))
                throw new ArgumentNullException("Domain");
            if (String.IsNullOrWhiteSpace(value[2] as string))
                throw new ArgumentNullException("Container");

            NetBIOS = value[0] as string;
            Domain = value[1] as string;
            Container = value[2] as string;
            Username = value[3] as string;
            Password = value[4] as string;
            SecureConnection = bool.Parse(value[5] as string ?? "False");
        }

        public DomainCredential(string netBios, string domain, string container)
            : this(netBios, domain, container, null, null, false)
        {
        }

        public DomainCredential(string netBios, string domain, string container, string username)
            : this(netBios, domain, container, username, null, false)
        {
        }

        public DomainCredential(string netBios, string domain, string container, string username, string password)
            : this(netBios, domain, container, username, password, false)
        {
        }

        public DomainCredential(string netBios, string domain, string container, string username, string password, bool secureConnection)
        {
            if (String.IsNullOrWhiteSpace(netBios))
                throw new ArgumentNullException("netBios");
            if (String.IsNullOrWhiteSpace(domain))
                throw new ArgumentNullException("domain");
            if (String.IsNullOrWhiteSpace(container))
                throw new ArgumentNullException("container");

            Container = container;
            Domain = domain;
            NetBIOS = netBios;
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