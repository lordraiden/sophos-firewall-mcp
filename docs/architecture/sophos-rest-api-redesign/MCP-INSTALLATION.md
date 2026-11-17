# MCP installation — why the panel does not list the Sophos server, and the standard registration

**Status:** diagnosis complete; migration not applied (read-only investigation).
**Date:** 15 November 2026.
**Scope:** DSH profile `web`, `dsh-skill-mcp-panel` 2.3.12, `@deepseek-ai/dsh-mcp-client`,
`sophos-firewall-mcp-server` 0.5.0 (STDIO).
**Nothing was modified:** the profile, the bundle and every source file are untouched. This
document is the only write.

---

## 1. Summary

The Sophos MCP server is **running correctly** and is **not misconfigured**. It is mounted from a
*configuration-only bundle* (`@local/sophos-firewall-mcp`), whose patch is composed by the DSH
loader as a **separate layer at boot**. The `dsh-skill-mcp-panel` plugin does not read that layer:
it reads exactly one file — `<profile>/cordis.patch.yml` — and lists only the
`@deepseek-ai/dsh-mcp-client` rows it finds there. The bundle's row lives in
`.agents/dsh-mcp-bundle/sophos-firewall-mcp/cordis.patch.yml`, so the panel cannot see it. This is
a **hard limitation of the panel's discovery model in 2.3.12**, not a broken installation.

The standard registration is a single `@deepseek-ai/dsh-mcp-client` row in
`/home/raiden/.dsh/profiles/web/cordis.patch.yml`, which the panel then lists, edits, toggles and
removes like any other server. It can be written by `dsh-panel mcp add …` or by the panel's Web UI.
**In this sandbox that write is blocked** (`~/.dsh` is mounted read-only: `EROFS`), so the command
must be run from a normal shell or from the panel UI in the host process.

---

## 2. The two configuration layers

DSH composes the effective plugin list from several ordered layers. The relevant ones, in
application order:

| Order | Layer | Where it lives |
|---|---|---|
| 1 | Bundle patches (one per entry in `dsh.profile.bundles`) | `<profile>/node_modules/<bundle>/cordis.patch.yml` |
| 2 | **Profile patch file** | `<profile>/cordis.patch.yml` |
| 3 | Global patch file | `$DSH_HOME/cordis.patch.yml` |
| 4 | Launch-time overlays | in-memory |

Evidence — `@deepseek-ai/dsh-app-boot`, `lib/index.js`:

```js
// lib/index.js:1913
function readProfilePatches(binName, context, initialProfile) {
	const patches = structuredClone([
		...readBundlePatches(binName, context, initialProfile),          // layer 1
		...initialProfile?.patches ?? loadOptionalPatches(binName, context.patchPath) ?? [],  // layer 2
		...loadOptionalPatches(binName, join(context.home, "cordis.patch.yml")) ?? [],        // layer 3
		...context.overlays
	]);
	…
}
```

`readBundlePatches` (`lib/index.js:1904`) returns `layers.flatMap((layer) => layer.patches)` — the
bundle patches are **read at boot and composed in memory**. They are never copied into the profile
patch file. `PROFILE_PATCH_FILENAME = "cordis.patch.yml"` (`lib/index.js:1332`) is the only file the
profile layer owns.

This is confirmed by the current profile state:

- `/home/raiden/.dsh/profiles/web/package.json:45` lists `"@local/sophos-firewall-mcp"` in
  `dsh.profile.bundles` (and `:10` as a `link:` dependency).
- `/home/raiden/.dsh/profiles/web/cordis.patch.yml` contains **no** `sophos` row at all
  (`grep -n sophos` → no match).
- The row exists only in
  `.agents/dsh-mcp-bundle/sophos-firewall-mcp/cordis.patch.yml`.

So the server mounts (its 98 read-only tools are live as `mcp__sophos__*`) while the profile patch
file — the only file the panel reads — says nothing about it.

---

## 3. How the panel discovers MCP servers

`dsh-skill-mcp-panel` 2.3.12, installed at
`/home/raiden/.dsh/profiles/web/node_modules/dsh-skill-mcp-panel`.

### 3.1 It reads exactly one file

`lib/mcp/gateway.js:66`:

```js
patchPath() {
    const base = this.C.baseUrl;
    if (typeof base === "string" && base.length > 0) {
        try {
            const url = new URL(base);
            if (url.protocol === "file:")
                return join(fileURLToPath(url), "cordis.patch.yml");
        }
        catch { /* fall through */ }
    }
    const packageDir = fileURLToPath(new URL("../../", import.meta.url));
    return join(resolve(packageDir, "../.."), "cordis.patch.yml");
}
```

Both branches resolve to `<profile>/cordis.patch.yml`. The CLI uses the same path
(`lib/cli-mcp.js:23`):

```js
function profilePatchPath(profile) {
    return join(resolveDshHome(), "profiles", profile, "cordis.patch.yml");
}
```

There is no second source: no `mcpServers` block, no registry, no loader enumeration.

### 3.2 It lists every `@deepseek-ai/dsh-mcp-client` row in that file

`lib/mcp/gateway.js:81` (`readRows`) reads the file and calls `listMcpPatchRows(raw)`;
`lib/patch-editor.js:223`:

```js
export function listMcpPatchRows(raw) {
    const doc = parseDocument(raw, { logLevel: "silent", customTags: YAML_CUSTOM_TAGS });
    if (doc.errors.length > 0) return [];
    const parsed = doc.toJS();
    if (!Array.isArray(parsed)) return [];
    return flattenPatchRows(parsed).filter((row) => row.name === MCP_PLUGIN_NAME);
}
```

with `MCP_PLUGIN_NAME = "@deepseek-ai/dsh-mcp-client"` (`lib/patch-editor.js:18`).

`flattenPatchRows` (`lib/patch-editor.js:101`) accepts **both** shapes:

- a top-level entry: `- id: … / name: '@deepseek-ai/dsh-mcp-client' / config: …`
- a member of an `insert:` list: `- insert: [ { id: …, name: '@deepseek-ai/dsh-mcp-client', … } ]`

The row is identified by `name`, and its server name by `config.serverName` (falling back to the
`panel-mcp-*` id suffix). An `id` is **not** required: since v2.3.6 every `@deepseek-ai/dsh-mcp-client`
row is manageable, inside or outside the managed block, with or without an `id`
(`README.en.md:205`, `:264`).

### 3.3 The list is built only from those rows

`lib/mcp/gateway.js:147`:

```js
async list() {
    let patch = { path: this.patchPath(), ok: false, error: null, foreign: [] };
    try {
        const { path, all, foreign } = await this.readRows();
        …
        const servers = [];
        for (const row of all) { … servers.push(view); }
        return { servers, externalServers: [], patch };
    }
    …
}
```

`externalServers` is hard-coded to `[]` — there is no "servers the loader knows about but the file
does not" channel. The panel's Web UI and its CLI share this code path, so both show the same set.

### 3.4 How it writes a new row

`lib/mcp/gateway.js:208` → `writeManagedRows(this.patchPath(), nextRows)`: new servers are appended
to the managed block delimited by `# >>> dsh-skill-mcp-panel:mcp:begin` /
`# <<< dsh-skill-mcp-panel:mcp:end` (`lib/patch-editor.js:16-17`), with the id
`panel-mcp-<serverName>` (`lib/mcp/model.js:133`, `toPatchRow` at `:197`). Existing rows are edited
in place, byte for byte (`replaceMcpEntryWithRow`), never rewritten wholesale.

---

## 4. Diagnosis

**The panel does not list the Sophos server because the server is registered in a bundle patch, and
the panel only reads the profile patch file.**

Chain of evidence:

1. The row is in `.agents/dsh-mcp-bundle/sophos-firewall-mcp/cordis.patch.yml`, not in
   `/home/raiden/.dsh/profiles/web/cordis.patch.yml` (`grep -n sophos` on the profile patch → no
   match).
2. `install_bundle` added the package to `dsh.profile.bundles`
   (`/home/raiden/.dsh/profiles/web/package.json:45`) and left the profile patch untouched — by
   design: bundle patches are a separate layer (`dsh-app-boot/lib/index.js:1904`, `:1913`).
3. The panel's `patchPath()` (`lib/mcp/gateway.js:66`) resolves to the profile patch file only, and
   `list()` (`:147`) enumerates only `listMcpPatchRows(raw)` from that file.
4. Therefore the row is invisible to the panel, while the loader still mounts it — which is why the
   `mcp__sophos__*` tools work and the bundle appears under **Plugins**.

Observed directly with the panel's own CLI (read-only):

```
$ node /home/raiden/.dsh/profiles/web/node_modules/dsh-skill-mcp-panel/lib/cli.js mcp list --profile web
启用       unraid-server       streamable-http       http://10.10.10.10:8043/mcp/${credential:MCP_UNRAID_TOKEN}
```

Only `unraid-server` — the one row that lives in the profile patch's managed block
(`cordis.patch.yml:216-236`). `sophos` is absent.

**This is not a bug in the bundle and not a panel defect to work around by editing the bundle.** The
panel's contract is "every MCP server entry in the profile `cordis.patch.yml`", and the bundle
deliberately keeps its row out of that file.

---

## 5. The standard registration

### 5.1 File

```
/home/raiden/.dsh/profiles/web/cordis.patch.yml
```

### 5.2 Row shape

The canonical shape, as the panel writes it (inside the managed block, id `panel-mcp-<serverName>`):

```yaml
- insert:
    - id: panel-mcp-sophos
      name: '@deepseek-ai/dsh-mcp-client'
      inject:
        - credentials
      config:
        serverName: sophos
        toolCallTimeoutMs: 60000
        failOnStartupError: true
        reconnect:
          enabled: true
          initialDelayMs: 500
          maxDelayMs: 30000
          maxAttempts: 10
        transport: stdio
        command: /home/raiden/.local/bin/uvx
        args:
          - --refresh-package
          - sophos-firewall-mcp-server
          - --from
          - git+https://github.com/lordraiden/sophos-firewall-mcp@main
          - sophos-firewall-mcp-server
        env:
          SOPHOS_HOST: 10.10.10.1
          SOPHOS_PORT: '443'
          SOPHOS_API_KEY: ${credential:SOPHOS_API_KEY}
          SOPHOS_VERIFY_SSL: 'false'
          SOPHOS_READ_ONLY_MODE: 'false'
          UV_TOOL_DIR: /home/raiden/Projects/sophos-firewall-mcp/.agents/uv-tools
          UV_CACHE_DIR: /home/raiden/Projects/sophos-firewall-mcp/.agents/uv-cache
        expandTemplates: true
        cwd: ''
```

This is the shape in use since 17 November 2026: the package is fetched from GitHub at start-up
(`uvx --from git+…@main`, with `--refresh-package` forcing a re-resolution so a restart picks up new
commits), and the key comes from the DSH credential store rather than a file on disk. The earlier
local-venv form (`command: …/.agents/mcp-venv/bin/sophos-firewall-mcp-server`, `args: []`,
`SOPHOS_API_KEY_FILE: …`) still works but is no longer what the profile uses.

The equivalent hand-written form — a **top-level** entry, outside the managed block — is also fully
listed and manageable (v2.3.6+), and is the shape the bundle already uses:

```yaml
- id: sophos-firewall-mcp
  name: '@deepseek-ai/dsh-mcp-client'
  inject:
    - credentials
  config:
    serverName: sophos
    transport: stdio
    command: /home/raiden/.local/bin/uvx
    args:
      - --refresh-package
      - sophos-firewall-mcp-server
      - --from
      - git+https://github.com/lordraiden/sophos-firewall-mcp@main
      - sophos-firewall-mcp-server
    env:
      SOPHOS_HOST: 10.10.10.1
      SOPHOS_PORT: '443'
      SOPHOS_API_KEY: ${credential:SOPHOS_API_KEY}
      SOPHOS_VERIFY_SSL: 'false'
      SOPHOS_READ_ONLY_MODE: 'false'
    expandTemplates: true
    failOnStartupError: true
```

Both are valid. The first is what the panel's own writer produces and is the one to prefer when the
panel is the management surface; the second is what to paste if the CLI is unavailable. `cwd: ''` is
the schema default (`@deepseek-ai/dsh-mcp-client`, `cwd: z.string().default("")`), so omitting it is
equivalent.

To narrow the published tool surface, add `SOPHOS_TOOL_DOMAINS` to the same `env` map — for example
`SOPHOS_TOOL_DOMAINS: firewall,nat,objects,network,audit` publishes 104 tools instead of 112, and
combining it with `SOPHOS_READ_ONLY_MODE: 'true'` publishes the 70 read-only tools of those five
domains. Leaving it unset keeps the complete surface. The accepted identifiers, the validation rules
and the per-domain counts are in the README's "Domain selection" section.

### 5.3 CLI command

`dsh-panel mcp add` supports exactly this, non-interactively (`README.en.md:174-205`,
`lib/cli-mcp.js:140-240`):

```bash
dsh-panel mcp add \
  --name sophos \
  --stdio \
  --command /home/raiden/.local/bin/uvx \
  --args --refresh-package \
  --args sophos-firewall-mcp-server \
  --args --from \
  --args git+https://github.com/lordraiden/sophos-firewall-mcp@main \
  --args sophos-firewall-mcp-server \
  --env SOPHOS_HOST=10.10.10.1 \
  --env SOPHOS_PORT=443 \
  --env 'SOPHOS_API_KEY=${credential:SOPHOS_API_KEY}' \
  --env SOPHOS_VERIFY_SSL=false \
  --env SOPHOS_READ_ONLY_MODE=false \
  --fail-on-startup \
  --profile web
```

`mcp add` has no flag for `inject` or `expandTemplates`, and a row that references
`${credential:…}` needs both. Add the row with the command above, then finish it with the raw editor:

```bash
dsh-panel mcp raw sophos --profile web > /tmp/sophos-row.yml
# add `inject: [credentials]` at row level and `expandTemplates: true` under `config`
dsh-panel mcp raw sophos --profile web --set /tmp/sophos-row.yml
```

`raw --set` replaces the whole row, so the file must contain every field the row needs. This is the
supported path: it keeps the panel's markers and its managed block intact, which a hand edit of
`cordis.patch.yml` does not guarantee.

Notes on the flags, from `lib/cli-mcp.js:140`:

- `--args` is repeatable and may be omitted (the server takes no arguments).
- `--env KEY=VALUE` is repeatable. A value containing `${NAME}` is stored as a `!!js` expression
  evaluated by the host at load time; a value starting with `!!js ` is passed through verbatim. Plain
  values are stored as strings, so `SOPHOS_PORT=443` becomes `'443'` and `SOPHOS_VERIFY_SSL=false`
  becomes `'false'` — exactly the quoted strings the bundle uses.
- `--fail-on-startup` sets `failOnStartupError: true`. It is implemented but missing from the
  README's usage block; it is the flag that reproduces the bundle's `failOnStartupError: true`.
- `--timeout <ms>` sets `toolCallTimeoutMs` (default `60000`).
- `--profile web` is mandatory and must name an existing profile; a typo is refused rather than
  creating a new profile (`lib/cli-mcp.js:281-295`).

**Invocation gotcha (verified).** `dsh-panel` is not on `PATH` here (`npm prefix -g` is
`/home/raiden/.nvm/versions/node/v26.13.1`, and no `dsh-panel` shim exists there). The profile-local
symlink `<profile>/node_modules/.bin/dsh-panel` **silently does nothing**: `lib/cli.js` only runs
when `process.argv[1]` resolves to the real `cli.js` path, and through the symlink it does not — the
command exits `0` with no output. Use the real path or a working shim:

```bash
node /home/raiden/.dsh/profiles/web/node_modules/dsh-skill-mcp-panel/lib/cli.js mcp add … --profile web
```

### 5.4 Can the CLI do it here?

**No.** `~/.dsh` is mounted read-only for bash tool calls in this session:

```
$ touch /home/raiden/.dsh/profiles/web/cordis.patch.yml
touch: setting times of '/home/raiden/.dsh/profiles/web/cordis.patch.yml': Read-only file system

$ dsh --profile web --dump-config
Error: EROFS: read-only file system, open '/home/raiden/.dsh/profiles/web/cordis.yml'
    at prepareProfile (…/dsh/lib/profile-boot-QhDEDXsF.js:221:2)
    at runDumpConfig (…/dsh/lib/dump-config-CKGOvlAq.js:25:17)
```

`dsh-panel mcp add` writes the same file through the same filesystem, so it would fail with `EROFS`
before changing anything. The write must be performed **outside this sandbox**: from a normal shell,
or from the panel's Web UI, which runs inside the DSH host process (not sandboxed) and writes the
file directly. The write was deliberately **not attempted** here, to avoid any chance of a partial
change.

---

## 6. Migration: bundle → standard registration

The two registrations must not coexist: `@deepseek-ai/dsh-mcp-client` rejects a second entry with the
same `serverName` ("the later one fails to load with a clear error", `dsh-mcp-client/README.md`).
Bundle patches apply **before** the profile patch, so a profile row added while the bundle is still
installed would be the later one and would fail. **Remove the bundle first, then add the row.**

1. **Record the current state** (for rollback):

   ```bash
   cp /home/raiden/.dsh/profiles/web/cordis.patch.yml /tmp/cordis.patch.yml.bak
   cp /home/raiden/.dsh/profiles/web/package.json     /tmp/package.json.bak
   ```

2. **Uninstall the bundle** — from the **Plugins** page (remove `@local/sophos-firewall-mcp`), or:

   ```bash
   dsh plugin --profile web remove @local/sophos-firewall-mcp
   ```

   This drops the `link:` dependency and the `dsh.profile.bundles` entry. The `mcp__sophos__*` tools
   disappear until step 3 — expected.

3. **Add the standard row** — from the panel UI (**MCP** → add server) or with the CLI from §5.3.
   The panel appends it to the managed block in `/home/raiden/.dsh/profiles/web/cordis.patch.yml`
   and hot-reloads the loader; no restart is needed.

4. **Verify**:

   ```bash
   node /home/raiden/.dsh/profiles/web/node_modules/dsh-skill-mcp-panel/lib/cli.js mcp list --profile web
   # expect a `sophos` row next to `unraid-server`

   node /home/raiden/.dsh/profiles/web/node_modules/dsh-skill-mcp-panel/lib/cli.js mcp test sophos --profile web
   ```

   Then, in a new session, call one read-only tool (e.g. `mcp__sophos__address_list_ipv4`) and confirm
   it returns 200.

5. **Keep the bundle directory** in the repository as a versioned artifact
   (`.agents/dsh-mcp-bundle/sophos-firewall-mcp/`) for other machines or for reinstalling, but leave
   it **uninstalled** in this profile. Do not reinstall it while the profile row exists.

### 6.1 Keeping the API key out of the profile file

The key never enters `cordis.patch.yml`. The row carries only a **reference**:

```yaml
inject:
  - credentials
config:
  env:
    SOPHOS_API_KEY: ${credential:SOPHOS_API_KEY}
  expandTemplates: true
```

The value lives in the DSH credential store (`~/.dsh/.credentials.yaml`, `refs.SOPHOS_API_KEY`,
mode `0600`), the same mechanism the `unraid-server` row uses for `MCP_UNRAID_TOKEN`. The store
resolves the reference at start-up and redacts the resolved value from diagnostics.

Keep it that way:

- Do **not** replace it with `SOPHOS_API_KEY: <literal>` — that would put the secret in a profile file
  that is backed up, synced and read by the panel.
- Do **not** paste the key into the panel's form or into `dsh-panel mcp add --env`; the CLI stores
  what it is given, in clear text.
- A row that references `${credential:…}` **needs** `inject: [credentials]` and `expandTemplates:
  true`. The panel's **form** rebuilds a row and drops `inject`, so such a row must be edited with
  **Raw** (or `dsh-panel mcp raw --set`), never with the form.
- The file-path alternative (`SOPHOS_API_KEY_FILE: …`) still works and needs no `inject`, but it
  leaves a second copy of the secret on disk. It was the setup until 17 November 2026; the duplicate
  file was removed when the credential store became the source of truth.

---

## 7. What could not be verified, and why

| Item | Why |
|---|---|
| The exact YAML `dsh-panel mcp add` emits | `~/.dsh` is read-only (`EROFS`), so the command could not be run. The row in §5.2 is derived from source (`toOfficialConfig` / `toPatchRow`, `lib/mcp/model.js:172-205`) and from the CLI's flag parsing (`lib/cli-mcp.js:140-240`), not observed. |
| The composed runtime configuration | `dsh --profile web --dump-config` fails with `EROFS` on `cordis.yml` (`prepareProfile` writes it). The layer order in §2 is read from `dsh-app-boot/lib/index.js:1904-1925`, not from a dump. |
| The panel's Web UI rendering | No browser control in this session. The UI's data source is the gateway `list()` (`lib/mcp/gateway.js:147`), which was read in source and exercised through the CLI, which shares `readRows`/`listMcpPatchRows`. |
| End-to-end success after migration | Would require modifying the profile. The server itself is already proven: a STDIO smoke test lists 98 read-only tools and a live read-only call returns 200, and the `mcp__sophos__*` tools are live in this session. |
| Whether the panel ever gains loader-based discovery | Not determinable from 2.3.12. `externalServers` is hard-coded `[]`; no such path exists in this version. |

---

## 8. Recommendation

**Migrate to the standard registration and keep the bundle as an uninstalled, versioned artifact.**

Rationale:

- The panel is the management surface the user actually uses. Only a row in
  `<profile>/cordis.patch.yml` is visible to it; a bundle row never will be in 2.3.12. Keeping the
  bundle means permanently losing enable/disable, form editing, Raw editing, `mcp test` and removal
  from the panel for this server.
- The profile row is the shape the official `@deepseek-ai/dsh-mcp-client` README documents as the
  minimal configuration, and it hot-reloads on save — no reinstall, no `pnpm link`.
- It removes a fragile coupling: the bundle is installed as
  `link:/home/raiden/Projects/sophos-firewall-mcp/.agents/dsh-mcp-bundle/sophos-firewall-mcp`, so the
  profile depends on a path inside a working tree. Moving or deleting that directory breaks the
  profile's dependency resolution. A profile row has no such dependency.
- The bundle's real value — reproducibility and versioning — is preserved by keeping the directory in
  the repository. It can be reinstalled on another machine, or restored here, by removing the profile
  row first.

Trade-off, stated plainly: with the profile row, the registration is **not** versioned with the
repository — it lives in `~/.dsh`, outside git. If reproducibility across machines matters more than
panel management, the alternative is to keep the bundle and accept that the panel will not list the
server; there is no configuration that gives both in 2.3.12. Given that the reported problem is
precisely the missing panel entry, the profile row is the right choice.

---

## Appendix — evidence commands

```bash
# 1. The row is not in the profile patch
grep -n sophos /home/raiden/.dsh/profiles/web/cordis.patch.yml        # → no match
grep -n sophos /home/raiden/.dsh/profiles/web/package.json            # → :10 (link:), :45 (bundles)

# 2. The row is in the bundle patch
cat /home/raiden/Projects/sophos-firewall-mcp/.agents/dsh-mcp-bundle/sophos-firewall-mcp/cordis.patch.yml

# 3. The panel lists only the profile patch's rows
node /home/raiden/.dsh/profiles/web/node_modules/dsh-skill-mcp-panel/lib/cli.js mcp list --profile web
# → 启用  unraid-server  streamable-http  http://10.10.10.10:8043/mcp/${credential:MCP_UNRAID_TOKEN}

# 4. The panel reads exactly one file
sed -n '66,90p'   /home/raiden/.dsh/profiles/web/node_modules/dsh-skill-mcp-panel/lib/mcp/gateway.js
sed -n '223,231p' /home/raiden/.dsh/profiles/web/node_modules/dsh-skill-mcp-panel/lib/patch-editor.js

# 5. Bundle patches are a separate layer, composed at boot
sed -n '1904,1925p' \
  /home/raiden/.nvm/versions/node/v26.13.1/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-app-boot/lib/index.js

# 6. The sandbox cannot write the profile
touch /home/raiden/.dsh/profiles/web/cordis.patch.yml   # → EROFS
dsh --profile web --dump-config                          # → EROFS on cordis.yml
```

### References

- `dsh-skill-mcp-panel` 2.3.12: `README.en.md:174-207` (MCP sub-commands, managed block, row
  ownership), `lib/mcp/gateway.js:66,81,147`, `lib/patch-editor.js:16-19,104,223`,
  `lib/cli-mcp.js:23,140-240,281`, `lib/mcp/model.js:133,172-205`.
- `@deepseek-ai/dsh-app-boot`: `lib/index.js:1332,1870,1904,1913`.
- `@deepseek-ai/dsh-mcp-client`: `README.md` — minimal configuration, field table, duplicate
  `serverName` behaviour, `cwd: z.string().default("")`.
- `dsh-doc` skill: `references/mcp-bundle.md` (configuration-only bundle route),
  `references/plugin-development.md` (do not hand-write the profile patch; `install_bundle` owns it).
