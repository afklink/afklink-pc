# Security policy

## Supported versions

Only the latest release receives security fixes. The app updates itself; if you build from
source, build from the latest release tag.

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue:

- on GitHub: the "Report a vulnerability" button on this repository's Security tab
  (private vulnerability reporting);
- by email: security@afklink.app.

Include the version or commit, what an attacker can achieve, and the steps or a proof of
concept that shows it. Reports about the AFKLink service itself (the server and the Telegram
Mini App) are welcome at the same address.

## What to expect

- We acknowledge a report within 3 working days.
- We send a first assessment within 10 working days.
- For a confirmed issue we agree a disclosure date with you, ship the fix in a release, and
  publish an advisory. We credit you in it unless you prefer otherwise.

## Safe harbor

We will not take legal action against you or ban your AFKLink account for security research
done in good faith and within this policy. That means you:

- test only against your own accounts, PCs and devices;
- access or keep no more data than you need to show the problem, and delete it afterwards;
- do not degrade the service for others (no denial-of-service or load testing);
- do not use social engineering, phishing or physical attacks;
- report to us privately and give us reasonable time to fix the issue before you disclose it.

## Trust model

- The PC app accepts a viewer only when the AFKLink server says that viewer is bound to this
  PC. The PC has no independent proof of the viewer's identity, so the AFKLink server is part
  of the trust boundary: whoever controls the server can open sessions on bound PCs.
- Each PC authenticates to the server by signing a server challenge with its own device key.
- An update is installed only if the downloaded exe carries a valid minisign signature made
  with the key pinned in the app. The signature covers the file, and its trusted comment names
  the file and the version, so a validly signed exe of another version is refused. The update
  manifest (`latest.json`) is not signed itself; the app also checks the exe against the
  SHA-256 and size listed there, and refuses to install a version older than the one it runs.
