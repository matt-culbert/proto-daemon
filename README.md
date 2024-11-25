### Use
Generate a user by running the pw_hash.py script
```bash
python pw_hash.py
```
Start the server
```bash
python server.py
```
Start the client and enter the username/password you generated
```bash
python client.py
```

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

### Compiling Go exe
#### Syntax
```bash
go build -ldflags "-X main.CompUUID=<ImplantID>" -tags <protocol> ./<dir>
```
#### Example
```bash
go build -ldflags "-X main.CompUUID=5678" -tags http ./http
```
#### Or using Garble
```bash
garble build -ldflags "-X main.CompUUID=5678" -tags http ./http
```

### Run the CF worker
```bash
npx wrangler dev .\cf-worker.js
```