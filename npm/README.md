# raxuiscli

Cybersecurity CLI toolkit for pentest, CTF, and security analysis — packaged for
npm. On install, a small script downloads the matching prebuilt native binary
from the [GitHub releases](https://github.com/Raxuis/RaxuisCLI/releases) and
verifies its checksum.

## Run without installing

```bash
npx raxuiscli tlsscan example.com
npx raxuiscli http headers https://example.com --output json
```

## Install globally

```bash
npm install -g raxuiscli
raxuiscli --help
```

## Supported platforms

| OS      | x64 | arm64 |
|---------|:---:|:-----:|
| Linux   |  ✓  |   ✓   |
| macOS   |  ✓  |   ✓   |
| Windows |  ✓  |   —   |

`tar` must be available on `PATH` (present by default on Linux, macOS, and
Windows 10+). Set `RAXUISCLI_SKIP_DOWNLOAD=1` to skip the binary download.

## Legal

For authorized security testing, CTF, and educational use only. See the
[main repository](https://github.com/Raxuis/RaxuisCLI) for full documentation
and the legal disclaimer.

## License

MIT
