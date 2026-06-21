# Authon Nim SDK

<p align="center">
  <img src="https://authon.pro/logo.png" alt="Authon" width="80" />
  <br/>
  <strong>Official Nim SDK for Authon — Software Licensing & Authentication Platform</strong>
</p>

<p align="center">
  <a href="https://authon.pro">Website</a> •
  <a href="https://authon.pro/docs">Docs</a> •
  <a href="https://discord.gg/MTY79JDFm6">Discord</a> •
  <a href="https://authon.pro/status">Status</a>
</p>

---

## Requirements

- Nim 1.6+
- stdlib only (httpclient, json, md5)

## Installation

Copy `authon.nim` into your project.

## Quick Start

```nim
import authon

let auth = newAuthon("your-app-id", "your-api-key")
if auth.init():
  echo "Connected: " & auth.appName

discard auth.login("username", "password")
echo "Level: " & $auth.level

discard auth.logout()
```

## Compile & Run

```bash
nim c -r example.nim
```

## Links

- 🌐 Website: https://authon.pro
- 📖 Docs: https://authon.pro/docs
- 💬 Discord: https://discord.gg/MTY79JDFm6
- 📊 Status: https://authon.pro/status

## License

MIT
