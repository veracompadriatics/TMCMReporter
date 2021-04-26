<#
.SYNOPSIS
	Generates CSV datasets from Trend Micro Control Manager (TMCM) database, 
	suitable for BI analysis in any of the popular tools (i.e. PowerBI)
.DESCRIPTION
	Connects to MSSQL TMCM database and performs a series of SQL queries,
	the results being dumped into standard CSV files (folder TMCM_CSVs relative to script path).
	These CSV files represent following datasets:
  - malware detection log
  - network virus detection log
  - a snapshot of endpoint count per server and subgroup
  These can be further
	processed by any BI analysis tool (Excel Pivot tables, PowerBI, etc).
.NOTES
	Configure database connection and other parameters below.
.LINK
	https://github.com/veracompadriatics/TMCMReporter
#>

$starttime='2021-01-01'; # start time to include data
$endtime='2021-03-31'; # end time to include data
$dbconfiguration=@{
    db_server=''; # SQL SERVER NAME OR IP ADDRESS
    db_name='db_ControlManager'; # TMCM DATABASE NAME    
}

# list of SQL queries used to get TMCM datasets of interest
$queries=@{
	# Malware detections
	"MalwareDetections"="IF Exists (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'temp_table')
BEGIN
	DROP TABLE temp_table
END;
SELECT B.Guid AS GUID, C.DisplayName AS DisplayName INTO temp_table
	FROM tb_TreeNode B INNER JOIN tb_TreeNode C
	ON B.ParentGuid = C.Guid
	WHERE (B.Type = 2);
IF Exists (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'temp_table2')
BEGIN
	DROP TABLE temp_table2
END;
SELECT B.Guid AS GUID, C.DisplayName AS DisplayName INTO temp_table2
	FROM tb_TreeNode B INNER JOIN tb_TreeNode C
	ON B.ParentGuid = C.Guid
	WHERE (B.Type = 4);
SELECT A.CLF_LogGenerationTime, D.DisplayName AS 'TMCMFolderName', C.DisplayName AS 'MgmtServer',
B.DisplayName AS 'Endpoint', F.EI_ProductVersion ProductVersion, E.DisplayName AS 'Domain',
A.VLF_VirusName AS 'MalwareName',
CASE
WHEN A.VLF_FilePath LIKE '%:\Windows\%' THEN 'System'
WHEN A.VLF_FileName LIKE '%:\Windows\%' THEN 'System'
WHEN A.VLF_FilePath LIKE '%:\Documents and Settings\%' THEN 'Profile'
WHEN A.VLF_FileName LIKE '%:\Documents and Settings\%' THEN 'Profile'
WHEN A.VLF_FilePath LIKE '%:\Users\%' THEN 'Profile'
WHEN A.VLF_FileName LIKE '%:\Users\%' THEN 'Profile' 
WHEN A.VLF_FilePath LIKE '%:\Program Files\%' THEN 'Program Files'
WHEN A.VLF_FileName LIKE '%:\Program Files\%' THEN 'Program Files'
ELSE 'Other'
END AS 'FilePath'
FROM temp_table D, temp_table2 E, dbo.tb_AVVirusLog A
INNER JOIN tb_TreeNode B ON A.VLF_ClientGUID=B.Guid
INNER JOIN tb_TreeNode C ON A.CLF_EntityID=C.Guid
INNER JOIN tb_EntityInfo F ON B.Guid = F.EI_EntityID
WHERE A.CLF_EntityID = D.Guid and A.VLF_ClientGUID=E.Guid
--AND CLF_LogGenerationTime>='$starttime' AND CLF_LogGenerationTime<='$endtime'
ORDER BY A.CLF_LogGenerationTime
"
	# Network virus attacks grouped by DATETIME, NETWORK ATTACK NAME, IP ADDRESS
	"NetworkVirusDetections"="SELECT  CVW_FromTime, 
dbo.tb_CVW_Log.VLF_VirusName AS 'AttackName', dbo.tb_CVW_Log.VLF_InfectionSource AS 'Endpoint', CVW_VirusCount AS 'Count'
FROM dbo.tb_CVW_Log 
WHERE 
--CVW_FromTime>='$starttime' AND CVW_FromTime<='$endtime' AND		
(VLF_InfectionSource like '10.%' OR VLF_InfectionSource like '192.168.%' OR VLF_InfectionSource like '172.%') 
UNION ALL
SELECT LogGenLocalDatetime, 
dbo.tb_PersonalFirewallLog.VirusName AS 'AttackName', SourceIP AS 'Endpoint', AggregatedCount AS 'Count'
FROM dbo.tb_PersonalFirewallLog
WHERE 
--LogGenLocalDatetime>='$starttime' AND LogGenLocalDatetime<='$endtime' AND
(SourceIP like '10.%' OR SourceIP like '192.168.%' OR SourceIP like '172.%') AND EventType=2"
	# C&C detections grouped by DATETIME, ENDPOINT, TMCM FOLDER, DOMAIN, SOURCE TYPE
	"CnCDetections"="IF Exists (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'temp_table')
		BEGIN
		DROP TABLE temp_table
		END;
		SELECT B.Guid AS GUID, C.DisplayName AS DisplayName INTO temp_table
		FROM tb_TreeNode B INNER JOIN tb_TreeNode C
		ON B.ParentGuid = C.Guid
		WHERE (B.Type = 2);
		IF Exists (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'temp_table2')
		BEGIN
		DROP TABLE temp_table2
		END;
		SELECT B.Guid AS GUID, C.DisplayName AS DisplayName INTO temp_table2
		FROM tb_TreeNode B INNER JOIN tb_TreeNode C
		ON B.ParentGuid = C.Guid
		WHERE (B.Type = 4);
		SELECT 
		A.CLF_LogGenerationUTCTime AS 'DateTime', 
		C.DisplayName, B.DisplayName AS 'Endpoint', D.DisplayName AS 'TMCMFolderName', E.DisplayName AS 'Domain', 
		CASE
			WHEN A.SLF_CCCA_DetectionSource=0 THEN 'Global'
			WHEN A.SLF_CCCA_DetectionSource=1 THEN 'Virtual Analyzer'
			WHEN A.SLF_CCCA_DetectionSource=2 THEN 'User Defined'
			ELSE 'Other'
		END AS 'DetectionSourceType'
		FROM temp_table D, temp_table2 E, dbo.tb_CnCDetection A
		INNER JOIN tb_TreeNode B ON A.SLF_ClientGUID=B.Guid
		INNER JOIN tb_TreeNode C ON A.SLF_ProductGUID=C.Guid
		WHERE A.SLF_ProductGUID = D.Guid and A.SLF_ClientGUID=E.Guid
		-- AND CLF_LogGenerationUTCTime>='$starttime' AND CLF_LogGenerationUTCTime<='$endtime'"
	# Number of Officescan endpoints per FOLDER, DOMAIN, VERSION
	"EndpointsBy-Folder-Domain-Version"="
	SELECT E.DisplayName TMCMFolderName, C.DisplayName Domain, F.EI_ProductVersion ProductVersion, COUNT(*) AS EndpointCount
		FROM tb_TreeNode B
		INNER JOIN tb_TreeNode C ON B.ParentGuid = C.Guid
		INNER JOIN tb_TreeNode D ON C.ParentGuid = D.Guid
		INNER JOIN tb_TreeNode E ON D.ParentGuid = E.Guid
		INNER JOIN tb_EntityInfo F ON B.Guid = F.EI_EntityID
		WHERE (B.Type = 4)
	GROUP BY C.DisplayName, E.DisplayName, F.EI_ProductVersion"
}

# EXECUTE ALL DEFINED SQL QUERIES
# OUTPUT EACH SQL QUERY INTO CSV FILE, ALL LOCATED IN FOLDER TMCM_CSVs
$currentpath = split-path -parent $MyInvocation.MyCommand.Definition # path of currently executing script
$csvpath="$($currentpath)\TMCM_CSVs";
If (!(Test-Path $csvpath)) {New-Item $csvpath -type directory}
$logfile="$currentpath\$($dbconfiguration.db_name).log";
If (Test-Path $logfile) {Clear-Content $logfile;}
$DataSet = New-Object System.Data.DataSet
$queries.Keys | ForEach-Object  {
	try {
		$sqlqueryname=$_;
		$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
		#$SqlConnection.ConnectionString = "Server=$($dbconfiguration.db_server); Database=$($dbconfiguration.db_name); Integrated Security=False; User ID=$($dbconfiguration.db_user); Password=$($dbconfiguration.db_pass);";
		$SqlConnection.ConnectionString = "Server=$($dbconfiguration.db_server); Database=$($dbconfiguration.db_name); Integrated Security=True;";
		$SqlConnection.Open()
		$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
		$SqlCmd.CommandText=$queries.Item($sqlqueryname)
		$SqlCmd.Connection = $SqlConnection
		$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
		$SqlAdapter.SelectCommand = $SqlCmd		
		$SqlAdapter.Fill($DataSet,$sqlqueryname) > $null| Out-Null
		$SqlConnection.Close()
	}
	catch {
		$ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
		"ERROR executing SQL statement '$($sqlqueryname)' on database name '$($dbconfiguration.db_name)', server '$($dbconfiguration.db_server)'. Details: $ErrorMessage ; $FailedItem" | Out-File -Append -filepath $logfile;
	}
}

$DataSet.Tables | ForEach-Object {
$_ | export-csv "$csvpath\$($_.TableName).csv" -notypeinformation
}
