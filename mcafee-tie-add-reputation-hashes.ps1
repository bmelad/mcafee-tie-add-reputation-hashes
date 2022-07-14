$epo = "your-epo-server"
$port = 8443
$user = "epo-username"
$password = "epo-password"

$reputationValue = 1 # Available reputations values are: 1 - Known Malicious, 15 - Most Likely Malicious, 30 - Might Be Malicious, 50 - Unknown, 70 - Might Be Trusted, 86 - Most Likely Trusted, 99 - Known Trusted
$reputationComment = "added by automation script"
$authorization = "Basic " + [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($user + ":" + $password))

Add-Type -AssemblyName System.Web

function GetHashType($hash) {
	if ($hash -match '^[A-Fa-f0-9]{64}$') { return "sha256" }
	elseif ($hash -match '^[A-Fa-f0-9]{40}$') { return "sha1" }
	elseif ($hash -match '^[A-Fa-f0-9]{32}$') { return "md5" }
	return "unknown hash type"
}

function Hex2Base64($hash) {
	$bytes = [byte[]] -split ($hash -replace '..', '0x$& ')
	return [System.Convert]::ToBase64String($bytes)
}

function SetReputation($hash) {
	$hashType = GetHashType($hash)
	if ($hashType -eq "unknown hash type") {
		write-host "invalid hash"
	} else {
		$base64 =  Hex2Base64($hash)
		$fileReps = '[{"reputation": "' + $reputationValue + '", "comment": "' + $reputationComment + '", "' + $hashType + '": "' + $base64 + '"}]'
		$url = "https://" + $epo + ":" + $port + "/remote/tie.setReputations?fileReps=" + [System.Web.HttpUtility]::UrlEncode($fileReps)
		$params = @{uri = $url; method = "GET"; headers = @{ Authorization = $authorization }}
		$result = Invoke-RestMethod @params
		echo $result
		if ($result -contains "Successfully set") {
			return $true
		} else {
			return $false
		}
	}
}

if ($args.count -gt 0) {
	$args | foreach-object {
		$currHash = $_;
		if (SetReputation($currHash)) {
		echo "$currHash - ok"
		} else {
			echo "$currHash - failed"
		}
	}
} else {
	foreach($currHash in get-content .\hashes.txt) {
		if (SetReputation($currHash)) {
			echo "$currHash - ok"
		} else {
			echo "$currHash - failed"
		}
	}
}
