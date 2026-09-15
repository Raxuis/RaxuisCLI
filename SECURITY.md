# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not through public issues or pull
requests.

- Preferred: open a private advisory via GitHub → the repository's **Security**
  tab → **Report a vulnerability** (GitHub Private Vulnerability Reporting).
- Include: affected version or commit, a description, reproduction steps, and
  the impact you observed.

You can expect an initial acknowledgement within a few days. Once a fix is
available, the advisory will be published and credited unless you ask otherwise.

## Supported versions

RaxuisCLI is pre-1.0 and ships from the `main` branch. Only the latest release
and the current `main` are supported. Fixes are not backported to older tags.

## Scope

RaxuisCLI is an **offensive security toolkit** meant for authorized testing,
CTFs, and research. In-scope reports include, for example:

- A command that leaks secrets it was given (for instance, unmasked cookies,
  keys, or tokens written to reports, logs, or terminal output).
- The passive `audit`/`demo` paths contacting a host other than the requested
  target, or the demo leaving loopback.
- Path traversal or unintended file writes from an output path or archive
  extraction.
- Memory-unsafe or panicking behavior triggerable by untrusted input.

Out of scope: the tool performing the offensive actions it is documented to
perform when a user runs it against a target. Using RaxuisCLI against systems
you do not own or have explicit permission to test is your responsibility, not a
vulnerability in the tool (see the Legal Disclaimer in the README).

## Handling of sensitive data

The audit and report layer redacts query values, cookies, authorization
headers, and embedded URL credentials, and the guided interface masks secret
values in its command previews. If you find a path where sensitive input still
escapes into a report, log, or preview, that is in scope — please report it.
