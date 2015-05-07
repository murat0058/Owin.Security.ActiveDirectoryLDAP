using System;
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

        internal static ClaimsIdentity GetClaimsIdentity(this UserPrincipal user, string authenticationType, string domain, string issuer = null, SerializationFormat serializationFormat = SerializationFormat.Json)
        {
            if (user.Guid.HasValue == false)
                throw new MissingFieldException("UserPrincipal is missing a Guid.");
            if (user.Sid == null)
                throw new MissingFieldException("UserPrincipal is missing a Sid.");

            //var context = user.Context;

            var identity = new ClaimsIdentity(authenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            //This is required for ASP.NET Identity, it should be a value unique to each user.
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Guid.Value.ToString(), ClaimValueTypes.String));
            identity.AddClaim(new Claim(ClaimTypes.PrimarySid, user.Sid.Value, ClaimValueTypes.Sid));
            identity.AddClaim(new Claim(ClaimTypesAD.BadLogonCount, user.BadLogonCount.ToString(), ClaimValueTypes.Integer32));//can this be set via a webapp? part of ValidateCredentials?
            identity.AddClaim(new Claim(ClaimTypesAD.Domain, domain, ClaimValueTypes.String));
            identity.AddClaim(new Claim(ClaimTypesAD.Enabled, (user.Enabled ?? false).ToString(), ClaimValueTypes.Boolean));//default? is a null value considered disabled?
            identity.AddClaim(new Claim(ClaimTypesAD.Guid, user.Guid.Value.ToString(), ClaimValueTypes.String));//unique per user? vs SID? https://technet.microsoft.com/en-us/library/cc961625.aspx sid can change "sometimes"
            identity.AddClaim(new Claim(ClaimTypesAD.LockedOut, user.IsAccountLockedOut().ToString(), ClaimValueTypes.Boolean));
            identity.AddClaim(new Claim(ClaimTypesAD.SmartcardLogonRequired, user.SmartcardLogonRequired.ToString(), ClaimValueTypes.Boolean));//Deny? How could we handle this.

            //Change to ClaimTypes.GroupSid? GroupGuid? We would either need a way to lookup the group based on the sid, or whatever attribute or other mechanism is used to set groups for actions to get and store the sid (e.g. on startup)
            identity.AddClaims(user.GetAuthorizationGroups().Select(_ => new Group(_).ToClaim(serializationFormat)));//GetGroups = Direct groups, GetAuthorizationGroups = recursive groups (speed?)

            if (!String.IsNullOrEmpty(user.Description))
                identity.AddClaim(new Claim(ClaimTypesAD.Description, user.Description, ClaimValueTypes.String));//job title?
            if (!String.IsNullOrEmpty(user.DisplayName))
                identity.AddClaim(new Claim(ClaimTypesAD.DisplayName, user.DisplayName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.DistinguishedName))
                identity.AddClaim(new Claim(ClaimTypesAD.DistinguishedName, user.DistinguishedName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.EmailAddress))
                identity.AddClaim(new Claim(ClaimTypes.Email, user.EmailAddress, ClaimValueTypes.Email));
            if (!String.IsNullOrEmpty(user.EmployeeId))
                identity.AddClaim(new Claim(ClaimTypesAD.EmployeeId, user.EmployeeId, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.GivenName))
                identity.AddClaim(new Claim(ClaimTypes.GivenName, user.GivenName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.HomeDirectory))
                identity.AddClaim(new Claim(ClaimTypesAD.HomeDirectory, user.HomeDirectory, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.HomeDrive))
                identity.AddClaim(new Claim(ClaimTypesAD.HomeDrive, user.HomeDrive, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.MiddleName))
                identity.AddClaim(new Claim(ClaimTypesAD.MiddleName, user.MiddleName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.Name))
                identity.AddClaim(new Claim(ClaimTypes.Name, user.Name, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.SamAccountName))
                identity.AddClaim(new Claim(ClaimTypesAD.SamAccountName, user.SamAccountName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.Surname))
                identity.AddClaim(new Claim(ClaimTypes.Surname, user.Surname, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.UserPrincipalName))
                identity.AddClaim(new Claim(ClaimTypesAD.UserPrincipalName, user.UserPrincipalName, ClaimValueTypes.String));
            if (!String.IsNullOrEmpty(user.VoiceTelephoneNumber))
                identity.AddClaim(new Claim(ClaimTypesAD.VoicePhone, user.VoiceTelephoneNumber, ClaimValueTypes.String));//WorkPhone? Format? e.g. https://en.wikipedia.org/wiki/E.123 or https://en.wikipedia.org/wiki/Microsoft_telephone_number_format
            if (user.AccountExpirationDate.HasValue)
                identity.AddClaim(new Claim(ClaimTypesAD.AccountExpiration, user.AccountExpirationDate.RoundTripString(), ClaimValueTypes.DateTime));//ClaimTypes.Expiration?
            if (user.AccountLockoutTime.HasValue)
                identity.AddClaim(new Claim(ClaimTypesAD.AccountLockout, user.AccountLockoutTime.RoundTripString(), ClaimValueTypes.DateTime));
            if (user.LastBadPasswordAttempt.HasValue)
                identity.AddClaim(new Claim(ClaimTypesAD.LastBadPassword, user.LastBadPasswordAttempt.RoundTripString(), ClaimValueTypes.DateTime));
            if (user.LastLogon.HasValue)
                identity.AddClaim(new Claim(ClaimTypesAD.LastLogon, user.LastLogon.RoundTripString(), ClaimValueTypes.DateTime));
            if (user.LastPasswordSet.HasValue)
                identity.AddClaim(new Claim(ClaimTypesAD.LastPasswordSet, user.LastPasswordSet.RoundTripString(), ClaimValueTypes.DateTime));
            if (user.PermittedLogonTimes != null)
                identity.AddClaim(LogonTimes.PermittedLogonTimes(user.PermittedLogonTimes).ToClaim(serializationFormat));

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
