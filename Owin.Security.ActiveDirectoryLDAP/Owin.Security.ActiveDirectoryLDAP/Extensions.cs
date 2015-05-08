using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace Owin.Security.ActiveDirectoryLDAP
{
    internal static class Extensions
    {
        internal static Guid GetUserGuid(this ClaimsIdentity identity)
        {
            var claim = identity.Claims.SingleOrDefault(_ => _.Type == ClaimTypes.NameIdentifier);
            if (claim == null)
                return default(Guid);
            return new Guid(claim.Value);
        }

        internal static SecurityIdentifier GetUserSid(this ClaimsIdentity identity)
        {
            var claim = identity.Claims.SingleOrDefault(_ => _.Type == ClaimTypes.NameIdentifier);
            if (claim == null)
                return default(SecurityIdentifier);
            return new SecurityIdentifier(claim.Value);
        }

        internal static string GetUserDomain(this ClaimsIdentity identity)
        {
            var claim = identity.Claims.SingleOrDefault(_ => _.Type == ClaimTypesAD.Domain);
            if (claim == null)
                return default(string);
            return claim.Value;
        }

        //internal static string GetUserGuid(this ClaimsIdentity identity)
        //{
        //    var claim = identity.Claims.SingleOrDefault(_ => _.Type == ClaimTypes.NameIdentifier);
        //    if (claim == null)
        //        return default(string);
        //    return claim.Value;
        //}

        //internal static string GetUserSid(this ClaimsIdentity identity)
        //{
        //    var claim = identity.Claims.SingleOrDefault(_ => _.Type == ClaimTypes.NameIdentifier);
        //    if (claim == null)
        //        return default(string);
        //    return claim.Value;
        //}

        internal static bool IsValid(this UserPrincipal user)//TODO: Output reason?
        {
            if (user.IsAccountLockedOut() || user.Enabled == false || (user.AccountExpirationDate ?? DateTime.MaxValue) < DateTime.UtcNow)
                return false;
            return true;
        }

        internal static IList<Claim> GetClaims(this UserPrincipal user, SerializationFormat serializationFormat = SerializationFormat.Json)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            if (user.Guid.HasValue == false)
                throw new MissingFieldException("UserPrincipal is missing a Guid.");
            if (user.Sid == null)
                throw new MissingFieldException("UserPrincipal is missing a Sid.");

            var claims = new List<Claim>();

            //This is required for ASP.NET Identity, it should be a value unique to each user.
            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Guid.Value.ToString(), ClaimValueTypes.String));
            claims.Add(new Claim(ClaimTypes.PrimarySid, user.Sid.Value, ClaimValueTypes.Sid));
            claims.Add(new Claim(ClaimTypesAD.BadLogonCount, user.BadLogonCount.ToString(), ClaimValueTypes.Integer32));//can this be set via a webapp? part of ValidateCredentials?
            claims.Add(new Claim(ClaimTypesAD.Enabled, (user.Enabled ?? false).ToString(), ClaimValueTypes.Boolean));//default? is a null value considered disabled?
            claims.Add(new Claim(ClaimTypesAD.Guid, user.Guid.Value.ToString(), ClaimValueTypes.String));//unique per user? vs SID? https://technet.microsoft.com/en-us/library/cc961625.aspx sid can change "sometimes"
            claims.Add(new Claim(ClaimTypesAD.LockedOut, user.IsAccountLockedOut().ToString(), ClaimValueTypes.Boolean));
            claims.Add(new Claim(ClaimTypesAD.SmartcardLogonRequired, user.SmartcardLogonRequired.ToString(), ClaimValueTypes.Boolean));//Deny? How could we handle this.

            //Change to ClaimTypes.GroupSid? GroupGuid? We would either need a way to lookup the group based on the sid, or whatever attribute or other mechanism is used to set groups for actions to get and store the sid (e.g. on startup)
            var securityGroups = user.GetAuthorizationGroups().Cast<GroupPrincipal>();
            claims = claims.Union(securityGroups.Select(_ => new Group(_).ToClaim(serializationFormat))).ToList();
            //claims = claims.Union(securityGroups.Select(_ => new Claim(ClaimTypes.GroupSid, _.Sid.Value, ClaimValueTypes.Sid))).ToList();

            //Is the first group the primary group? It seems so in testing but I'm not sure if that can be relied on.
            //var primaryGroup = securityGroups.FirstOrDefault();
            //if (primaryGroup != null)
            //    claims.Add(new Claim(ClaimTypes.PrimaryGroupSid, primaryGroup.Sid.Value, ClaimValueTypes.Sid));

            if (!String.IsNullOrEmpty(user.Description))
                claims.Add(new Claim(ClaimTypesAD.Description, user.Description, ClaimValueTypes.String));//job title?
            if (!String.IsNullOrEmpty(user.DisplayName))
                claims.Add(new Claim(ClaimTypesAD.DisplayName, user.DisplayName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.DistinguishedName))
                claims.Add(new Claim(ClaimTypesAD.DistinguishedName, user.DistinguishedName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.EmailAddress))
                claims.Add(new Claim(ClaimTypes.Email, user.EmailAddress, ClaimValueTypes.Email));
            if (!String.IsNullOrEmpty(user.EmployeeId))
                claims.Add(new Claim(ClaimTypesAD.EmployeeId, user.EmployeeId, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.GivenName))
                claims.Add(new Claim(ClaimTypes.GivenName, user.GivenName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.HomeDirectory))
                claims.Add(new Claim(ClaimTypesAD.HomeDirectory, user.HomeDirectory, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.HomeDrive))
                claims.Add(new Claim(ClaimTypesAD.HomeDrive, user.HomeDrive, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.MiddleName))
                claims.Add(new Claim(ClaimTypesAD.MiddleName, user.MiddleName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.Name))
                claims.Add(new Claim(ClaimTypes.Name, user.Name, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.SamAccountName))
                claims.Add(new Claim(ClaimTypesAD.SamAccountName, user.SamAccountName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.Surname))
                claims.Add(new Claim(ClaimTypes.Surname, user.Surname, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.UserPrincipalName))
                claims.Add(new Claim(ClaimTypesAD.UserPrincipalName, user.UserPrincipalName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.VoiceTelephoneNumber))
                claims.Add(new Claim(ClaimTypesAD.VoicePhone, user.VoiceTelephoneNumber, ClaimValueTypes.String));//WorkPhone? Format? e.g. https://en.wikipedia.org/wiki/E.123 or https://en.wikipedia.org/wiki/Microsoft_telephone_number_format
            if (user.AccountExpirationDate.HasValue)
                claims.Add(new Claim(ClaimTypesAD.AccountExpiration, user.AccountExpirationDate.RoundTripString(), ClaimValueTypes.DateTime));//ClaimTypes.Expiration?
            if (user.AccountLockoutTime.HasValue)
                claims.Add(new Claim(ClaimTypesAD.AccountLockout, user.AccountLockoutTime.RoundTripString(), ClaimValueTypes.DateTime));
            if (user.LastBadPasswordAttempt.HasValue)
                claims.Add(new Claim(ClaimTypesAD.LastBadPassword, user.LastBadPasswordAttempt.RoundTripString(), ClaimValueTypes.DateTime));
            if (user.LastLogon.HasValue)
                claims.Add(new Claim(ClaimTypesAD.LastLogon, user.LastLogon.RoundTripString(), ClaimValueTypes.DateTime));
            if (user.LastPasswordSet.HasValue)
                claims.Add(new Claim(ClaimTypesAD.LastPasswordSet, user.LastPasswordSet.RoundTripString(), ClaimValueTypes.DateTime));
            if (user.PermittedLogonTimes != null)
                claims.Add(LogonTimes.PermittedLogonTimes(user.PermittedLogonTimes).ToClaim(serializationFormat));

            return claims;
        }

        internal static ClaimsIdentity GetClaimsIdentity(this UserPrincipal user, string authenticationType, string domain, string issuer = null, SerializationFormat serializationFormat = SerializationFormat.Json)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            if (user.Guid.HasValue == false)
                throw new MissingFieldException("UserPrincipal is missing a Guid.");
            if (user.Sid == null)
                throw new MissingFieldException("UserPrincipal is missing a Sid.");

            //var context = user.Context;

            var identity = new ClaimsIdentity(authenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            identity.AddClaim(new Claim(ClaimTypesAD.Domain, domain, ClaimValueTypes.String));
            identity.AddClaims(user.GetClaims(serializationFormat));

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
