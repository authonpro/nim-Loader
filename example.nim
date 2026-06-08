import authon, strutils

let auth = newAuthon("your-app-id", "your-api-key")

if not auth.init():
  echo "[-] Connection failed"
  quit(1)

echo "[+] Connected: " & auth.appName & " v" & auth.appVersion
echo "\n[1] Login\n[2] License Key"
stdout.write("\n> ")
let choice = readLine(stdin).strip()

if choice == "1":
  stdout.write("Username: "); let u = readLine(stdin).strip()
  stdout.write("Password: "); let p = readLine(stdin).strip()
  let res = auth.login(u, p)
  if not res{"success"}.getBool: echo "[-] " & res{"message"}.getStr; quit(1)
else:
  stdout.write("License Key: "); let k = readLine(stdin).strip()
  let res = auth.license(k)
  if not res{"success"}.getBool: echo "[-] " & res{"message"}.getStr; quit(1)

echo "\n[+] Authenticated! Level: " & $auth.level
let msg = auth.getVar("welcome_message")
if msg != "": echo "[*] " & msg
discard auth.log("Nim SDK example executed")
echo "[+] Done."
discard auth.logout()
