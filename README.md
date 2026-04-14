# GuiPortFwd
#### Simple GUI based Port Forwarding tool for developers
#### This project aims to Forward a Port which is running on a local Windows machine.
#####   This can be easily access via LAN router within the same network which Access devices ans machine on.
![Image1](/gui1.png)
Before Started
![Image2](/gui2.png)
After Started
### Run this on PowerShell (if there is an issue, run on Powershell as run as administrator)
```sh
cargo run
```
```sh
# If needed, the binary will be at target\release\portfwd.exe
cargo build --release
```
#### Run the server (Eg:- for FastAPI server)
###### Any type of server is possible by setting IP to 127.0.0.1 and port to 8080
```sh
uvicorn src.main:app --host 127.0.0.1 --port 8080
```
#### Open following to access the server withing the same LAN(Local area network) aka WiFi router.
```sh
http://192.168.1.10:9000/
```
### If need to check connections (Run on Powershell as run as administrator)
```sh
netstat -ano | findstr :8080
```
### If an issue is occurring try the following command on Powershell as run as administrator
```sh
netsh advfirewall firewall show rule name=portfwd-8080
```
### If Windows IIS interferes
```sh
# Press Win, type "powershell", right-click → "Run as administrator", then:
iisreset /stop
```
