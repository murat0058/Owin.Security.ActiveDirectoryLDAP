param (
    [string]$SolutionDir = $(throw "`$SolutionDir is required."),
    [string]$TargetPath = $(throw "`$TargetPath is required.")
)

$xmlFile = $SolutionDir + "\Owin.Security.ActiveDirectoryLDAP.nuspec"
$xml = NEW-OBJECT XML
$xml.PreserveWhitespace = $true;
$xml.load($xmlFile);

$ns = NEW-OBJECT System.Xml.XmlNamespaceManager($xml.NameTable);
$ns.AddNamespace("ns", $xml.DocumentElement.NamespaceURI);

$xmlVersion = $xml.selectSingleNode("//ns:version", $ns);
if ($xmlVersion -ne $null) {
    $version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$TargetPath").FileVersion;
    $xmlVersion.InnerText = $version;
    $xml.save($xmlFile);
}
