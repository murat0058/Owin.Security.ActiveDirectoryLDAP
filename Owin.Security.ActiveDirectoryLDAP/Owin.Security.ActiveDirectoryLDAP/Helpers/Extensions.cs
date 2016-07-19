using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public static class Extensions
    {
        public static Guid GetGuid(this ClaimsIdentity identity)
        {
            var claim = identity.Claims.SingleOrDefault(_ => _.Type == ClaimTypes.NameIdentifier);
            if (claim == null)
                return default(Guid);
            return new Guid(claim.Value);
        }

        public static SecurityIdentifier GetSid(this ClaimsIdentity identity)
        {
            var claim = identity.Claims.SingleOrDefault(_ => _.Type == ClaimTypes.PrimarySid);
            if (claim == null)
                return default(SecurityIdentifier);
            return new SecurityIdentifier(claim.Value);
        }

        public static string GetDomain(this ClaimsIdentity identity)
        {
            var claim = identity.Claims.SingleOrDefault(_ => _.Type == ClaimTypesAD.Domain);
            if (claim == null)
                return default(string);
            return claim.Value;
        }

        public static string GetDisplayName(this ClaimsIdentity identity)
        {
            var claim = identity.Claims.SingleOrDefault(_ => _.Type == ClaimTypesAD.DisplayName);
            if (claim == null)
                return default(string);
            return claim.Value;
        }

        internal static bool IsValid(this UserPrincipal user, SecurityIdentifier sid = null)//TODO: Output reason?
        {
            if (user.IsAccountLockedOut() || user.Enabled == false || (user.AccountExpirationDate ?? DateTime.MaxValue) < DateTime.UtcNow || (sid != null && user.Sid != sid))
                return false;
            return true;
        }

        internal static IList<Claim> GetClaims(this UserPrincipal user, IList<string> claimTypes, SerializationFormat serializationFormat = SerializationFormat.Json)
        {
            claimTypes = claimTypes ?? new List<string>();

            if (user == null)
                throw new ArgumentNullException("user");
            if (user.Guid.HasValue == false)
                throw new MissingFieldException(Resource.MissingUserPrincipalGuid);
            if (user.Sid == null)
                throw new MissingFieldException(Resource.MissingUserPrincipalSid);

            var claims = new List<Claim>();

            //Generate here from the SameAccountName instead of passing it through?
            //claims.Add(new Claim(ClaimTypes.Name, user.Name, ClaimValueTypes.String));

            //This is required for ASP.NET Identity, it should be a value unique to each user. https://technet.microsoft.com/en-us/library/cc961625.aspx SID can change "sometimes", Guid should never change.
            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Guid.Value.ToString(), ClaimValueTypes.String));
            claims.Add(new Claim(ClaimTypes.PrimarySid, user.Sid.Value, ClaimValueTypes.Sid));
            claims.Add(new Claim(ClaimTypesAD.Guid, user.Guid.Value.ToString(), ClaimValueTypes.String));

            var securityGroups = user.GetAuthorizationGroups().Cast<GroupPrincipal>();

            claims = claims.Union(securityGroups.Select(_ => {
                //TODO: Need a better way to get netbios domain from DistinguishedName
                var domain = Owin.Security.ActiveDirectoryLDAP.TEST.DomainCredentials.FirstOrDefault(d => _ != null && !String.IsNullOrEmpty(_.DistinguishedName) && _.DistinguishedName.EndsWith(d.Container, StringComparison.OrdinalIgnoreCase));
                if (domain != null)
                    return new Claim(ClaimsIdentity.DefaultRoleClaimType, domain.NetBIOS + @"\" + _.SamAccountName);
                return null;
            }).Where(_ => _ != null)).ToList();//will these always be security groups?

            //Is the first group the primary group? It seems so in testing but I'm not sure if that can be relied on.
            //var primaryGroup = securityGroups.FirstOrDefault();
            //if (primaryGroup != null)
            //    claims.Add(new Claim(ClaimTypes.PrimaryGroupSid, primaryGroup.Sid.Value, ClaimValueTypes.Sid));

            if (claimTypes.Contains(ClaimTypes.GroupSid) && securityGroups.Any())
                claims.AddRange(securityGroups.Select(_ => new Claim(ClaimTypes.GroupSid, _.Sid.Value, ClaimValueTypes.Sid)));// Union?
            if (claimTypes.Contains(ClaimTypesAD.BadLogonCount))
                claims.Add(new Claim(ClaimTypesAD.BadLogonCount, user.BadLogonCount.ToString(), ClaimValueTypes.Integer32));//can this be set via a webapp? part of ValidateCredentials?
            if (claimTypes.Contains(ClaimTypesAD.Enabled)/* && user.Enabled.HasValue*/)
                claims.Add(new Claim(ClaimTypesAD.Enabled, (user.Enabled ?? false).ToString(), ClaimValueTypes.Boolean));//default? is a null value considered disabled?
            if (claimTypes.Contains(ClaimTypesAD.LockedOut))
                claims.Add(new Claim(ClaimTypesAD.LockedOut, user.IsAccountLockedOut().ToString(), ClaimValueTypes.Boolean));
            if (claimTypes.Contains(ClaimTypesAD.SmartcardLogonRequired))
                claims.Add(new Claim(ClaimTypesAD.SmartcardLogonRequired, user.SmartcardLogonRequired.ToString(), ClaimValueTypes.Boolean));//Deny? How could we handle this.
            if (claimTypes.Contains(ClaimTypesAD.Description) && !String.IsNullOrEmpty(user.Description))
                claims.Add(new Claim(ClaimTypesAD.Description, user.Description, ClaimValueTypes.String));//job title?
            if (claimTypes.Contains(ClaimTypesAD.DisplayName) && !String.IsNullOrEmpty(user.DisplayName))
                claims.Add(new Claim(ClaimTypesAD.DisplayName, user.DisplayName, ClaimValueTypes.String));
            if (claimTypes.Contains(ClaimTypesAD.DistinguishedName) && !String.IsNullOrEmpty(user.DistinguishedName))
                claims.Add(new Claim(ClaimTypesAD.DistinguishedName, user.DistinguishedName, ClaimValueTypes.String));
            if (claimTypes.Contains(ClaimTypes.Email) && !String.IsNullOrEmpty(user.EmailAddress))
                claims.Add(new Claim(ClaimTypes.Email, user.EmailAddress, ClaimValueTypes.Email));
            if (claimTypes.Contains(ClaimTypesAD.EmployeeId) && !String.IsNullOrEmpty(user.EmployeeId))
                claims.Add(new Claim(ClaimTypesAD.EmployeeId, user.EmployeeId, ClaimValueTypes.String));
            if (claimTypes.Contains(ClaimTypes.GivenName) && !String.IsNullOrEmpty(user.GivenName))
                claims.Add(new Claim(ClaimTypes.GivenName, user.GivenName, ClaimValueTypes.String));
            if (claimTypes.Contains(ClaimTypesAD.HomeDirectory) && !String.IsNullOrEmpty(user.HomeDirectory))
                claims.Add(new Claim(ClaimTypesAD.HomeDirectory, user.HomeDirectory, ClaimValueTypes.String));
            if (claimTypes.Contains(ClaimTypesAD.HomeDrive) && !String.IsNullOrEmpty(user.HomeDrive))
                claims.Add(new Claim(ClaimTypesAD.HomeDrive, user.HomeDrive, ClaimValueTypes.String));
            if (claimTypes.Contains(ClaimTypesAD.MiddleName) && !String.IsNullOrEmpty(user.MiddleName))
                claims.Add(new Claim(ClaimTypesAD.MiddleName, user.MiddleName, ClaimValueTypes.String));
            if (claimTypes.Contains(ClaimTypesAD.SamAccountName) && !String.IsNullOrEmpty(user.SamAccountName))
                claims.Add(new Claim(ClaimTypesAD.SamAccountName, user.SamAccountName, ClaimValueTypes.String));
            if (claimTypes.Contains(ClaimTypes.Surname) && !String.IsNullOrEmpty(user.Surname))
                claims.Add(new Claim(ClaimTypes.Surname, user.Surname, ClaimValueTypes.String));
            if (claimTypes.Contains(ClaimTypesAD.UserPrincipalName) && !String.IsNullOrEmpty(user.UserPrincipalName))
                claims.Add(new Claim(ClaimTypesAD.UserPrincipalName, user.UserPrincipalName, ClaimValueTypes.String));
            if (claimTypes.Contains(ClaimTypesAD.VoicePhone) && !String.IsNullOrEmpty(user.VoiceTelephoneNumber))
                claims.Add(new Claim(ClaimTypesAD.VoicePhone, user.VoiceTelephoneNumber, ClaimValueTypes.String));//WorkPhone? Format? e.g. https://en.wikipedia.org/wiki/E.123 or https://en.wikipedia.org/wiki/Microsoft_telephone_number_format
            if (claimTypes.Contains(ClaimTypesAD.AccountExpiration) && user.AccountExpirationDate.HasValue)
                claims.Add(new Claim(ClaimTypesAD.AccountExpiration, user.AccountExpirationDate.RoundTripString(), ClaimValueTypes.DateTime));//ClaimTypes.Expiration?
            if (claimTypes.Contains(ClaimTypesAD.AccountLockout) && user.AccountLockoutTime.HasValue)
                claims.Add(new Claim(ClaimTypesAD.AccountLockout, user.AccountLockoutTime.RoundTripString(), ClaimValueTypes.DateTime));
            if (claimTypes.Contains(ClaimTypesAD.LastBadPassword) && user.LastBadPasswordAttempt.HasValue)
                claims.Add(new Claim(ClaimTypesAD.LastBadPassword, user.LastBadPasswordAttempt.RoundTripString(), ClaimValueTypes.DateTime));
            if (claimTypes.Contains(ClaimTypesAD.LastLogon) && user.LastLogon.HasValue)
                claims.Add(new Claim(ClaimTypesAD.LastLogon, user.LastLogon.RoundTripString(), ClaimValueTypes.DateTime));
            if (claimTypes.Contains(ClaimTypesAD.LastPasswordSet) && user.LastPasswordSet.HasValue)
                claims.Add(new Claim(ClaimTypesAD.LastPasswordSet, user.LastPasswordSet.RoundTripString(), ClaimValueTypes.DateTime));
            if (claimTypes.Contains(ClaimTypesAD.PermittedLogonTimes) && user.PermittedLogonTimes != null)
                claims.Add(LogonTimes.PermittedLogonTimes(user.PermittedLogonTimes).ToClaim(serializationFormat));//TODO: series of claims instead of serialized?

            return claims;
        }

        internal static ClaimsIdentity GetClaimsIdentity(this UserPrincipal user, string authenticationType, IList<string> claimTypes, string domain, string issuer = null, SerializationFormat serializationFormat = SerializationFormat.Json)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            if (user.Guid.HasValue == false)
                throw new MissingFieldException(Resource.MissingUserPrincipalGuid);
            if (user.Sid == null)
                throw new MissingFieldException(Resource.MissingUserPrincipalSid);

            //var context = user.Context;

            var identity = new ClaimsIdentity(authenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            identity.AddClaim(new Claim(ClaimTypesAD.Domain, domain, ClaimValueTypes.String));//do we need this?
            identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, domain.ToUpperInvariant() + @"\" + user.SamAccountName.ToLowerInvariant()));//move to getclaims?
            identity.AddClaims(user.GetClaims(claimTypes, serializationFormat));

            return identity;
        }

        private static string RoundTripString(this DateTime? dateTime)
        {
            return dateTime.HasValue
                ? dateTime.Value.ToString("o")//DateTimeStyles.RoundtripKind, so it can be parsed back out easily.
                : default(string);
        }
    }
}
