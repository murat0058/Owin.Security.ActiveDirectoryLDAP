using System;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Claims;
using System.Text;

namespace Owin.Security.ActiveDirectoryLDAP
{
    [DataContract(Namespace = "http://schemas.wustl.edu/ws/2015/04/activedirectorygroup")]
    public class Group
    {
        public Group(Principal group)
            : this()
        {
            Description = group.Description;
            DisplayName = group.DisplayName;
            DistinguishedName = group.DistinguishedName;
            Guid = group.Guid.HasValue ? group.Guid.Value.ToString() : default(string);
            Name = group.Name;
            SamAccountName = group.SamAccountName;
            Sid = group.Sid.Value;
        }

        internal Group()
        {
        }

        [DataMember]
        public string Description { get; private set; }
        [DataMember]
        public string DisplayName { get; private set; }
        [DataMember]
        public string DistinguishedName { get; private set; }
        [DataMember]
        public string Guid { get; private set; }
        [DataMember]
        public string Name { get; private set; }
        [DataMember]
        public string SamAccountName { get; private set; }
        [DataMember]
        public string Sid { get; private set; }

        public static Group FromClaim(Claim claim)
        {
            //return null instead of throwing?
            if (claim.Type != ClaimTypesAD.ActiveDirectoryGroup)
                throw new ArgumentException("Invalid claim type.", "claim");
            //not a great thing to do
            if (claim.Value.StartsWith("{"))
                return FromJson(claim.Value);
            if (claim.Value.StartsWith("<"))
                return FromXml(claim.Value);
            throw new FormatException("Claim value format could not be detected.");
        }

        public static Group FromJson(string json)
        {
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                stream.Position = 0;
                return new DataContractJsonSerializer(typeof(Group)).ReadObject(stream) as Group;
            }
        }

        public static Group FromXml(string xml)
        {
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml)))
            {
                stream.Position = 0;
                return new DataContractSerializer(typeof(Group)).ReadObject(stream) as Group;
            }
        }

        public Claim ToClaim(SerializationFormat serializationFormat = SerializationFormat.Json)
        {
            return new Claim(ClaimTypes.GroupSid, Sid);

            //var serialized = serializationFormat == SerializationFormat.Json
            //    ? this.ToJson()
            //    : this.ToXml();
            //return new Claim(LDAPClaimTypes.ActiveDirectoryGroup, serialized);
        }

        public string ToJson()
        {
            using (var stream = new MemoryStream())
            {
                new DataContractJsonSerializer(typeof(Group)).WriteObject(stream, this);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }

        public string ToXml()
        {
            using (var stream = new MemoryStream())
            {
                new DataContractSerializer(typeof(Group)).WriteObject(stream, this);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }
    }
}
