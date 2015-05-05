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

        internal static ClaimsIdentity GetClaimsIdentity(this UserPrincipal user, string authenticationType, string issuer = null, SerializationFormat serializationFormat = SerializationFormat.Json)
        {
            //var groups1 = user.GetGroups();//TODO: Store these in claims identity somehow, serialized?
            //var groups2 = user.GetAuthorizationGroups();//difference?
            //var times1 = user.PermittedLogonTimes;//parse?
            //var times2 = PermittedLogonTimes.GetLogonTimes(times1);
            //var test1 = groups1.First().ToXml();
            //var test2 = groups1.First().ToJson();
            //var test3 = ActiveDirectoryGroup.FromXml(test1);
            //var test4 = ActiveDirectoryGroup.FromJson(test2);

            var test=  user.Context;

            var identity = new ClaimsIdentity(authenticationType);
            //This is required for ASP.NET Identity, it should be a value unique to each user.
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Guid.Value.ToString()));
            identity.AddClaim(new Claim(ClaimTypes.PrimarySid, user.Sid.Value));
            identity.AddClaim(new Claim(LDAPClaimTypes.BadLogonCount, user.BadLogonCount.ToString()));//can this be set via a webapp? part of ValidateCredentials?
            //identity.AddClaim(new Claim(LDAPClaimTypes.Domain, ))
            identity.AddClaim(new Claim(LDAPClaimTypes.Enabled, (user.Enabled ?? false).ToString()));//default? is a null value considered disabled?
            identity.AddClaim(new Claim(LDAPClaimTypes.Guid, user.Guid.Value.ToString()));//unique per user? vs SID? https://technet.microsoft.com/en-us/library/cc961625.aspx sid can change "sometimes"
            identity.AddClaim(new Claim(LDAPClaimTypes.LockedOut, user.IsAccountLockedOut().ToString()));
            identity.AddClaim(new Claim(LDAPClaimTypes.SmartcardLogonRequired, user.SmartcardLogonRequired.ToString()));//Deny? How could we handle this.

            //Change to ClaimTypes.GroupSid? GroupGuid? We would either need a way to lookup the group based on the sid, or whatever attribute or other mechanism is used to set groups for actions to get and store the sid (e.g. on startup)
            identity.AddClaims(user.GetAuthorizationGroups().Select(_ => new Group(_).ToClaim(serializationFormat)));//GetGroups = Direct groups, GetAuthorizationGroups = recursive groups (speed?)

            if (user.EmailAddress != null)
                identity.AddClaim(new Claim(ClaimTypes.Email, user.EmailAddress));
            if (user.GivenName != null)
                identity.AddClaim(new Claim(ClaimTypes.GivenName, user.GivenName));
            if (user.Name != null)
                identity.AddClaim(new Claim(ClaimTypes.Name, user.Name));
            if (user.Surname != null)
                identity.AddClaim(new Claim(ClaimTypes.Surname, user.Surname));
            if (user.AccountExpirationDate != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.AccountExpiration, user.AccountExpirationDate.Value.ToString("o")));//ClaimTypes.Expiration?
            if (user.AccountLockoutTime != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.AccountLockout, user.AccountLockoutTime.Value.ToString("o")));
            if (user.Description != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.Description, user.Description));//job title?
            if (user.DisplayName != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.DisplayName, user.DisplayName));
            if (user.DistinguishedName != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.DistinguishedName, user.DistinguishedName));
            if (user.EmployeeId != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.EmployeeId, user.EmployeeId));
            if (user.HomeDirectory != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.HomeDirectory, user.HomeDirectory));
            if (user.HomeDrive != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.HomeDrive, user.HomeDrive));
            if (user.LastBadPasswordAttempt != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.LastBadPassword, user.LastBadPasswordAttempt.Value.ToString("o")));
            if (user.LastLogon != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.LastLogon, user.LastLogon.Value.ToString("o")));
            if (user.LastPasswordSet != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.LastPasswordSet, user.LastPasswordSet.Value.ToString("o")));
            if (user.MiddleName != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.MiddleName, user.MiddleName));
            if (user.SamAccountName != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.SamAccountName, user.SamAccountName));
            if (user.UserPrincipalName != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.UserPrincipalName, user.UserPrincipalName));
            if (user.VoiceTelephoneNumber != null)
                identity.AddClaim(new Claim(LDAPClaimTypes.VoicePhone, user.VoiceTelephoneNumber));//WorkPhone? Format? e.g. https://en.wikipedia.org/wiki/E.123 or https://en.wikipedia.org/wiki/Microsoft_telephone_number_format
            if (user.PermittedLogonTimes != null)
                identity.AddClaim(LogonTimes.PermittedLogonTimes(user.PermittedLogonTimes).ToClaim());

            return identity;
        }
    }
}
