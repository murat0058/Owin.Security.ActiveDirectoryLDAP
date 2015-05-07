using System;

namespace Owin.Security.ActiveDirectoryLDAP
{
    public static class ClaimTypesAD
    {
        public const string AccountExpiration = ClaimTypeNamespace + "/accountexpiration";
        public const string AccountLockout = ClaimTypeNamespace + "/accountlockout";
        public const string ActiveDirectoryGroup = ClaimTypeNamespace + "/activedirectorygroup";
        public const string BadLogonCount = ClaimTypeNamespace + "/badlogoncount";
        public const string Description = ClaimTypeNamespace + "/description";
        public const string DisplayName = ClaimTypeNamespace + "/displayname";
        public const string DistinguishedName = ClaimTypeNamespace + "/distinguishedname";
        public const string Domain = ClaimTypeNamespace + "/domain";
        public const string EmployeeId = ClaimTypeNamespace + "/employeeid";
        public const string Enabled = ClaimTypeNamespace + "/enabled";
        public const string Guid = ClaimTypeNamespace + "/guid";
        public const string HomeDirectory = ClaimTypeNamespace + "/homedirectory";
        public const string HomeDrive = ClaimTypeNamespace + "/homedrive";
        public const string LastBadPassword = ClaimTypeNamespace + "/lastbadpassword";
        public const string LastLogon = ClaimTypeNamespace + "/lastlogon";
        public const string LastPasswordSet = ClaimTypeNamespace + "/lastpasswordsSet";
        public const string LockedOut = ClaimTypeNamespace + "/lockedout";
        public const string MiddleName = ClaimTypeNamespace + "/middlename";
        public const string PermittedLogonTimes = ClaimTypeNamespace + "permittedlogontimes";
        public const string SamAccountName = ClaimTypeNamespace + "/samaccountname";
        public const string SmartcardLogonRequired = ClaimTypeNamespace + "/smartcardlogonrequired";//Require client certificate auth?
        public const string UserPrincipalName = ClaimTypeNamespace + "/userprincipalname";
        public const string VoicePhone = ClaimTypeNamespace + "/voicephone";

        private const string ClaimTypeNamespace = "http://schemas.wustl.edu/ws/2015/04/identity/claims";
    }

    //public static class ClaimValueTypesAD
    //{
    //    public const string DsaKeyValue = "http://www.w3.org/2000/09/xmldsig#DSAKeyValue";
    //    public const string Email = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
    //    public const string Fqbn = "http://www.w3.org/2001/XMLSchema#fqbn";
    //
    //    internal const string ClaimValueTypeNamespace = "http://schemas.wustl.edu/ws/2015/04/identity/claims";
    //}
}
