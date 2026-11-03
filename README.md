# KeePassXC Search — an electerm widget

Look up logins in [KeePassXC](https://keepassxc.org) and open SSH, RDP or Telnet sessions in [electerm](https://github.com/electerm/electerm) with them, without storing passwords in electerm.

There is no UI in this folder: `electerm.configs` in `package.json` describes the form, electerm renders it and calls the functions in `main.js`.

```
package.json     metadata + form definition
main.js          widget actions
keepassxc.js     KeePassXC browser integration client (NaCl box, tweetnacl)
node_modules/    tweetnacl 1.0.3, committed with the widget
test.js          tests against a fake KeePassXC (node --test test.js)
```

## Install

**Settings → Widgets → Import**, then paste

```
mkneppe/electerm-widget-keepassxc
```

Needs electerm **v5.8.0+**. `tweetnacl` is committed in `node_modules` on purpose: import never runs `npm install`.

## Setup

1. In KeePassXC: **Settings → Browser Integration → Enable browser integration**. No browser has to be ticked.
2. Open and unlock your database.
3. Open the widget, press **Pair with KeePassXC** and confirm the request in KeePassXC with a name (e.g. `electerm`).

## Use

Enter a host or URL and press **Search**:

| Input | Looked up in KeePassXC |
| --- | --- |
| `server1` | `ssh://server1:22`, `rdp://server1:3389`, `telnet://server1:23`, `https://server1` |
| `server1:2222` | the same with port 2222, and `https://server1` |
| `rdp://10.0.0.5:3389` | just this URL |

An entry whose URL is only the host (`server1`) is found through `https://server1`: KeePassXC reads a URL without scheme as https. Best give entries URLs like `ssh://host:port` or `rdp://host:port`.

Each entry has the buttons **SSH**, **RDP**, **Telnet** (open a session with its user and password) and **Details** (user and password to copy). The port is taken from the URL when its scheme is the session type, else the default port.

If the database is locked, KeePassXC shows its unlock dialog.

## Security notes

- The widget talks to KeePassXC's socket (a named pipe on Windows) with its browser integration protocol, the one keepassxc-browser uses; everything after the key exchange is encrypted with NaCl box
- `.state.json` (next to `main.js`, mode 600) holds **only** the pairing id and key, never passwords or the master password. Re-importing the widget replaces the folder, then pair again
- Passwords stay in memory of electerm's main process until the next search or **Forget passwords**; table rows carry no passwords
- Tabs opened by a widget are tagged `from: widget:keepassxc-search`, electerm keeps them out of the connection history

## Known limitations

- No automatic lookup when a bookmark connects, and no saving of a new login after it worked: a widget is not told when a bookmark connects. `main.js` already has `getCredentials(target)` and `saveCredentials({ target, login, password })` for a credential-provider hook, discussed in electerm/electerm#4687
- KeePassXC finds entries by URL only, there is no search by title
