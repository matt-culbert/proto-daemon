### Before first use
This covers the initial setup of required things like the Python requirements and how to generate a user.

Install required Python modules
```bash
pip install -r requirements.txt
```
Install required Go packages
```bash
cd ./Implant; go mod tidy
```
Generate a user by running the pw_hash.py script
```bash
python Server/pw_hash.py
```
Generate the SSL cert for the server to secure connections with
```bash
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

### Run the application
1) First, start the server
```bash
python Server/server.py
```
2) After the server is started, start the client and enter the username/password you generated. The server needs to be run first since the client tries to authenticate after you enter your details.
```bash
python Client/client.py
```

### Powershell commands for simulating implant
These have proven handy for emulating implant testing to the server without having to run an implant itself. 
```powershell
$postParams = @{"msg" = "7465:7374::"}
$jsonPost = $postParams | ConvertTo-Json 
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add('Content-type','Application/Json')
Invoke-WebRequest -Uri http://127.0.0.1:5000/1234 -Method GET
Invoke-WebRequest -Uri http://127.0.0.1:5000/1234 -Method POST -Body $jsonPost -Headers $headers
```

### Compiling Go exe
These should be handled by the Makefile, but if you're curious about what's supported or you want to compile the implant manually, this is what's required.

There are tags and ldflags that setup things like the callback URLs, implant ID, and enable supported features.
#### Compile flag options
```bash
# Implant UUID
# Expects a random but unique 4 digit integer
-X main.CompUUID 
# POST URI to use 
# Default POST option is `/` or use other listeners you have made
-X main.PostURI 
# GET URI to use
# Default GET option is `/` or use other listeners you have made
-X main.GetURI
```
#### Compile tag options
```bash
# Enable zlib compression
withComp 
# Enable support for Lua scripting
withLua 
```
#### Syntax
```bash
go build -ldflags <ldflags> -tags <optional support> ./<dir>
```
#### Example
```bash
go build -ldflags "-X main.CompUUID=5678 -X main.PostURI=/ -X main.GetURI=/" -tags withComp withHttp ./Implant/daemon
```
#### Or using Garble
```bash
garble build -ldflags "-X main.CompUUID=5678 -X main.PostURI=/ -X main.GetURI=/" -tags withComp withHttp ./Implant/daemon
```
### Run the CF worker
The last point to review is the cloudflare worker script. This can be run in the Cloudflare environment but you will probably be banned. So run it locally instead.
```bash
npx wrangler dev .\cf-worker.js
```