## ╔══════════════════════════════════════════════════════════════════════════════╗
## ║  Authon Nim SDK — Software Licensing & Authentication                      ║
## ║  Version: 1.0.0                                                            ║
## ║  Dependencies: stdlib only (httpclient, json, md5)                         ║
## ║                                                                            ║
## ║  Website: https://authon.pro                                               ║
## ║  Docs:    https://authon.pro/docs                                          ║
## ║  Discord: https://discord.gg/jMZCTKPsmE                                    ║
## ║  Status:  https://authon.pro/status                                        ║
## ║  Health:  https://api.authon.pro/health                                    ║
## ║  GitHub:  https://github.com/authonpro                                     ║
## ║                                                                            ║
## ║  Usage:                                                                    ║
## ║    import authon                                                           ║
## ║    var client = newAuthon("app-id", "api-key")                             ║
## ║    client.init()                                                           ║
## ║    let session = client.login("user", "pass")                              ║
## ║    echo "Welcome! Level: " & $session.level                                ║
## ╚══════════════════════════════════════════════════════════════════════════════╝

import std/[httpclient, json, md5, os, osproc, strutils, tables]

const
  AuthonVersion* = "1.0.0"
  DefaultApiUrl* = "https://api.authon.pro/v1"
  DefaultTimeout* = 15000 # milliseconds

type
  AuthonError* = object of CatchableError
    ## Custom exception for Authon SDK errors.

  SessionData* = object
    ## Session data returned after successful authentication.
    sessionToken*: string  ## Unique session token
    username*: string      ## Authenticated username
    level*: int            ## User's access level (0+)
    subscription*: string  ## Subscription plan name
    expiresAt*: string     ## Expiration date (ISO 8601)

  AppInfo* = object
    ## Application info from init().
    name*: string          ## App name
    version*: string       ## App version
    hwidLock*: bool        ## HWID lock enabled
    hashCheck*: bool       ## Hash check enabled

  FileInfo* = object
    ## File entry from listFiles.
    id*: string            ## File ID
    name*: string          ## File name
    size*: int             ## File size in bytes
    minLevel*: int         ## Minimum level required

  OnlineData* = object
    ## Online users data.
    count*: int            ## Online user count
    users*: seq[string]    ## Online usernames

  StatsData* = object
    ## Application statistics.
    totalUsers*: int
    onlineUsers*: int
    totalKeys*: int
    appVersion*: string

  BlacklistData* = object
    ## Blacklist check result.
    blacklisted*: bool
    reason*: string

  ReferralData* = object
    ## Referral redemption result.
    expiresAt*: string
    rewardDays*: int
    message*: string

  AuthonClient* = ref object
    ## Main Authon SDK client.
    appId: string
    apiKey: string
    apiUrl: string
    timeout: int
    # Session state
    sessionToken*: string
    username*: string
    level*: int
    subscription*: string
    expiresAt*: string
    # App info
    appName*: string
    appVersion*: string
    hwidLock*: bool
    hashCheck*: bool
    initialized*: bool

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTRUCTOR
# ═══════════════════════════════════════════════════════════════════════════════

proc newAuthon*(appId, apiKey: string; apiUrl: string = DefaultApiUrl;
                timeout: int = DefaultTimeout): AuthonClient =
  ## Creates a new Authon client.
  ##
  ## Parameters:
  ##   appId  - Your Application ID from the Authon dashboard.
  ##   apiKey - Your API Key from the Authon dashboard.
  ##   apiUrl - Custom API URL (default: https://api.authon.pro/v1).
  ##   timeout - HTTP timeout in milliseconds (default: 15000).
  assert appId.len > 0, "appId is required"
  assert apiKey.len > 0, "apiKey is required"

  result = AuthonClient(
    appId: appId.strip(),
    apiKey: apiKey.strip(),
    apiUrl: apiUrl.strip(chars = {'/'}),
    timeout: timeout,
    level: 0,
    initialized: false,
  )

proc isAuthenticated*(client: AuthonClient): bool =
  ## Returns true if the client has an active session.
  client.sessionToken.len > 0

# ═══════════════════════════════════════════════════════════════════════════════
# HWID GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

proc getHWID*(): string =
  ## Generates a hardware ID unique to the current machine.
  ##
  ## Windows: disk serial + computer name.
  ## Linux: /etc/machine-id.
  ## macOS: system_profiler UUID.
  ##
  ## Returns a 32-character lowercase hex MD5 hash.
  var raw = ""

  when defined(windows):
    try:
      let output = execProcess("wmic diskdrive get serialnumber")
      let lines = output.splitLines()
      if lines.len > 1:
        raw = lines[1].strip()
    except:
      discard
    # Append computer name
    raw &= getEnv("COMPUTERNAME")
  elif defined(macosx):
    try:
      let output = execProcess("system_profiler SPHardwareDataType")
      for line in output.splitLines():
        if "UUID" in line:
          let parts = line.split(":")
          if parts.len >= 2:
            raw = parts[1].strip()
            break
    except:
      discard
    if raw.len == 0:
      raw = getEnv("USER") & hostOS
  else:
    # Linux
    if fileExists("/etc/machine-id"):
      raw = readFile("/etc/machine-id").strip()
    else:
      try:
        let hostname = execProcess("hostname").strip()
        raw = hostname & hostOS
      except:
        raw = getEnv("USER") & hostOS

  if raw.len == 0:
    raw = "fallback-" & hostOS

  result = $toMD5(raw)

# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL HTTP
# ═══════════════════════════════════════════════════════════════════════════════

proc request(client: AuthonClient; payload: JsonNode): JsonNode =
  ## Sends a POST request to the Authon API.
  var body = payload.copy()
  body["appId"] = %client.appId
  body["apiKey"] = %client.apiKey

  let httpClient = newHttpClient(timeout = client.timeout)
  httpClient.headers = newHttpHeaders({
    "Content-Type": "application/json",
    "User-Agent": "Authon-Nim-SDK/" & AuthonVersion
  })

  try:
    let response = httpClient.post(client.apiUrl, body = $body)
    result = parseJson(response.body)
  except HttpRequestError:
    raise newException(AuthonError, "Connection failed. Check https://authon.pro/status")
  except JsonParsingError:
    raise newException(AuthonError, "Invalid response from server")
  except:
    raise newException(AuthonError, "Unexpected error: " & getCurrentExceptionMsg())
  finally:
    httpClient.close()

proc checkSuccess(response: JsonNode) =
  ## Raises AuthonError if the response indicates failure.
  let success = response.getOrDefault("success").getBool(false)
  if not success:
    let message = response.getOrDefault("message").getStr("Unknown error")
    raise newException(AuthonError, message)

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

proc init*(client: AuthonClient): AppInfo =
  ## Initializes the connection to the Authon API.
  ## Must be called before any other API method.
  ##
  ## Returns AppInfo on success.
  ## Raises AuthonError on failure.
  let response = client.request(%*{"type": "init"})
  checkSuccess(response)

  let data = response["data"]
  result = AppInfo(
    name: data.getOrDefault("name").getStr(""),
    version: data.getOrDefault("version").getStr(""),
    hwidLock: data.getOrDefault("hwidLock").getBool(false),
    hashCheck: data.getOrDefault("hashCheck").getBool(false),
  )

  client.appName = result.name
  client.appVersion = result.version
  client.hwidLock = result.hwidLock
  client.hashCheck = result.hashCheck
  client.initialized = true

# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════

proc login*(client: AuthonClient; username, password: string;
            hwid: string = ""): SessionData =
  ## Authenticates with username and password.
  ##
  ## On success, sets client session state.
  ##
  ## Possible errors:
  ##   "Invalid credentials", "Account banned", "Hardware ID mismatch",
  ##   "Subscription expired", "Account is frozen",
  ##   "VPN/Proxy connections are not allowed"
  if username.len == 0 or password.len == 0:
    raise newException(AuthonError, "Username and password are required")

  let hw = if hwid.len > 0: hwid else: getHWID()

  let response = client.request(%*{
    "type": "login",
    "username": username,
    "password": password,
    "hwid": hw
  })
  checkSuccess(response)

  let data = response["data"]
  result = SessionData(
    sessionToken: data.getOrDefault("sessionToken").getStr(""),
    username: data.getOrDefault("username").getStr(""),
    level: data.getOrDefault("level").getInt(0),
    subscription: data.getOrDefault("subscription").getStr(""),
    expiresAt: data.getOrDefault("expiresAt").getStr(""),
  )

  client.sessionToken = result.sessionToken
  client.username = result.username
  client.level = result.level
  client.subscription = result.subscription
  client.expiresAt = result.expiresAt

proc license*(client: AuthonClient; licenseKey: string;
              hwid: string = ""): SessionData =
  ## Authenticates using a license key only.
  if licenseKey.len == 0:
    raise newException(AuthonError, "License key is required")

  let hw = if hwid.len > 0: hwid else: getHWID()

  let response = client.request(%*{
    "type": "license",
    "licenseKey": licenseKey,
    "hwid": hw
  })
  checkSuccess(response)

  let data = response["data"]
  result = SessionData(
    sessionToken: data.getOrDefault("sessionToken").getStr(""),
    username: data.getOrDefault("username").getStr(""),
    level: data.getOrDefault("level").getInt(0),
    subscription: data.getOrDefault("subscription").getStr(""),
    expiresAt: data.getOrDefault("expiresAt").getStr(""),
  )

  client.sessionToken = result.sessionToken
  client.username = result.username
  client.level = result.level
  client.subscription = result.subscription
  client.expiresAt = result.expiresAt

proc register*(client: AuthonClient; username, password, licenseKey: string;
               hwid: string = "") =
  ## Registers a new user account with a license key.
  if username.len == 0 or password.len == 0 or licenseKey.len == 0:
    raise newException(AuthonError, "Username, password, and licenseKey are required")

  let hw = if hwid.len > 0: hwid else: getHWID()

  let response = client.request(%*{
    "type": "register",
    "username": username,
    "password": password,
    "licenseKey": licenseKey,
    "hwid": hw
  })
  checkSuccess(response)

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

proc check*(client: AuthonClient): bool =
  ## Validates the current session (heartbeat).
  if client.sessionToken.len == 0: return false

  let response = client.request(%*{
    "type": "check",
    "sessionToken": client.sessionToken
  })
  result = response.getOrDefault("success").getBool(false)

proc logout*(client: AuthonClient) =
  ## Ends the current session and clears local state.
  if client.sessionToken.len == 0: return

  let response = client.request(%*{
    "type": "logout",
    "sessionToken": client.sessionToken
  })

  if response.getOrDefault("success").getBool(false):
    client.sessionToken = ""
    client.username = ""
    client.level = 0
    client.subscription = ""
    client.expiresAt = ""

# ═══════════════════════════════════════════════════════════════════════════════
# VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

proc getVar*(client: AuthonClient; key: string): string =
  ## Gets an application-level variable.
  let response = client.request(%*{
    "type": "var", "key": key, "sessionToken": client.sessionToken
  })
  checkSuccess(response)
  result = response["data"].getOrDefault("value").getStr("")

proc setVar*(client: AuthonClient; key, value: string) =
  ## Sets a user-level variable.
  let response = client.request(%*{
    "type": "setvar", "key": key, "value": value,
    "sessionToken": client.sessionToken
  })
  checkSuccess(response)

proc getUserVar*(client: AuthonClient; key: string): string =
  ## Gets a user-level variable.
  let response = client.request(%*{
    "type": "getvar", "key": key, "sessionToken": client.sessionToken
  })
  checkSuccess(response)
  result = response["data"].getOrDefault("value").getStr("")

# ═══════════════════════════════════════════════════════════════════════════════
# FILES
# ═══════════════════════════════════════════════════════════════════════════════

proc listFiles*(client: AuthonClient): seq[FileInfo] =
  ## Lists all files available to the authenticated user.
  let response = client.request(%*{
    "type": "list_files", "sessionToken": client.sessionToken
  })
  checkSuccess(response)

  result = @[]
  if response.hasKey("data") and response["data"].kind == JArray:
    for item in response["data"]:
      result.add(FileInfo(
        id: item.getOrDefault("id").getStr(""),
        name: item.getOrDefault("name").getStr(""),
        size: item.getOrDefault("size").getInt(0),
        minLevel: item.getOrDefault("minLevel").getInt(0),
      ))

proc downloadFile*(client: AuthonClient; fileId: string): string =
  ## Downloads a file by its ID. Returns raw bytes as string.
  if client.sessionToken.len == 0 or fileId.len == 0:
    raise newException(AuthonError, "Session and file ID are required")

  var body = %*{
    "type": "file",
    "appId": client.appId,
    "apiKey": client.apiKey,
    "fileId": fileId,
    "sessionToken": client.sessionToken
  }

  let httpClient = newHttpClient(timeout = 60000)
  httpClient.headers = newHttpHeaders({
    "Content-Type": "application/json",
    "User-Agent": "Authon-Nim-SDK/" & AuthonVersion
  })

  try:
    let response = httpClient.post(client.apiUrl, body = $body)
    let ct = response.headers.getOrDefault("content-type")
    if "octet-stream" in ct:
      return response.body
    # Try GET fallback
    let url = client.apiUrl & "/files/download/" & fileId & "?token=" & client.sessionToken
    let getResp = httpClient.get(url)
    let getCt = getResp.headers.getOrDefault("content-type")
    if "octet-stream" in getCt:
      return getResp.body
    raise newException(AuthonError, "File download failed")
  finally:
    httpClient.close()

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING & ANALYTICS
# ═══════════════════════════════════════════════════════════════════════════════

proc log*(client: AuthonClient; message: string) =
  ## Sends an activity log message to the dashboard.
  let msg = if message.len > 500: message[0..499] else: message
  let response = client.request(%*{
    "type": "log", "message": msg, "sessionToken": client.sessionToken
  })
  checkSuccess(response)

proc fetchOnline*(client: AuthonClient): OnlineData =
  ## Gets the list of currently online users.
  let response = client.request(%*{
    "type": "fetch_online", "sessionToken": client.sessionToken
  })
  checkSuccess(response)

  let data = response["data"]
  result.count = data.getOrDefault("count").getInt(0)
  result.users = @[]
  if data.hasKey("users") and data["users"].kind == JArray:
    for user in data["users"]:
      result.users.add(user.getStr(""))

proc fetchStats*(client: AuthonClient): StatsData =
  ## Gets application statistics.
  let response = client.request(%*{
    "type": "fetch_stats", "sessionToken": client.sessionToken
  })
  checkSuccess(response)

  let data = response["data"]
  result = StatsData(
    totalUsers: data.getOrDefault("totalUsers").getInt(0),
    onlineUsers: data.getOrDefault("onlineUsers").getInt(0),
    totalKeys: data.getOrDefault("totalKeys").getInt(0),
    appVersion: data.getOrDefault("appVersion").getStr(""),
  )

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

proc checkBlacklist*(client: AuthonClient; ip: string = "";
                     hwid: string = ""): BlacklistData =
  ## Checks if an IP or HWID is blacklisted.
  var payload = %*{"type": "check_blacklist"}
  if ip.len > 0: payload["ip"] = %ip
  if hwid.len > 0: payload["hwid"] = %hwid

  let response = client.request(payload)
  checkSuccess(response)

  let data = response["data"]
  result = BlacklistData(
    blacklisted: data.getOrDefault("blacklisted").getBool(false),
    reason: data.getOrDefault("reason").getStr(""),
  )

proc redeemReferral*(client: AuthonClient; code: string): ReferralData =
  ## Redeems a referral code for bonus subscription days.
  if code.len == 0:
    raise newException(AuthonError, "Referral code is required")

  let response = client.request(%*{
    "type": "redeem_referral",
    "code": code,
    "sessionToken": client.sessionToken
  })
  checkSuccess(response)

  let data = response["data"]
  result = ReferralData(
    expiresAt: data.getOrDefault("expiresAt").getStr(""),
    rewardDays: data.getOrDefault("rewardDays").getInt(0),
    message: response.getOrDefault("message").getStr(""),
  )
