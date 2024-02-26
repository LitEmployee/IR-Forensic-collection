$regkeys =  'HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords',
            'HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security\Trusted Documents\TrustRecords',
            'HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security\Trusted Documents\TrustRecords'
foreach ($key in $regkeys) {
        try {$item = Get-Item $key -erroraction stop} catch { $item = "" }
        foreach ($line in $item.property) {
            $values = $item.getvalue($line)
            if ($values[-1] -gt 0) {$type="RUN"} else {$type="EDIT"}
            $timestamp = [datetime]::FromFileTimeUtc([System.BitConverter]::ToUint64($values,0))
            Write-Output "$line $timestamp $type"
        }
}