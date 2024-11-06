### Generate cert
```shell
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```
### Powershell commands for simulating implant
```powershell
$postParams = @{"msg" = "7465:7374::"}
$jsonPost = $postParams | ConvertTo-Json 
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add('Content-type','Application/Json')
Invoke-WebRequest -Uri http://127.0.0.1:5000/1234 -Method GET
Invoke-WebRequest -Uri http://127.0.0.1:5000/1234 -Method POST -Body $jsonPost -Headers $headers
```

### Header generation
```bash
xxd -i config.txt > config_data.h
```

### Linking external CPP project files locally
Makes a hard link from the CPP project directory to the local directory holding the main Python project
```bash
mklink /H <link> <target>
```