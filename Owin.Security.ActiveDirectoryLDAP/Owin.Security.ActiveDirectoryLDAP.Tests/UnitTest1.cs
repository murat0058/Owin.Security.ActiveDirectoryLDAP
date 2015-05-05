using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Owin.Security.ActiveDirectoryLDAP.Tests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            byte[] test = { 0, 0, 0, 0, 224, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            //PermittedLogonTimes.GetLogonTimes(test);
            LogonTimes.PermittedLogonTimes(test);
        }
    }
}
