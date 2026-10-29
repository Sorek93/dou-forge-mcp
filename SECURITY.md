# Security boundaries — private alpha

No production deployment recommendation or external security certification is made.

* Administrator configuration, SSH configuration, identity provider and OS accounts are trusted.
  Model output, retrieved text, tool arguments and remote stdout/stderr are untrusted.
* HTTP auth uses the official SDK. JWT signatures are verified with an administrator-pinned HTTPS
  JWKS endpoint; issuer, audience, expiry, subject authorization and scope are mandatory. Key
  retrieval failures deny access. Private IPs are never an authentication exemption.
* The preview token mode is deliberately loopback-only and is not an OAuth authorization server.
  Never proxy/tunnel preview mode to other users. JWT-mode TLS proxy deployment needs operator review.
* Per-principal host/action lists authorize operations; arbitrary SSH aliases/options are not accepted.
  There is no implicit merge of every alias in the controller's SSH configuration.
* Local operator approval is not exposed as a model-callable tool. Plans bind caller/configuration,
  expire, and can only be consumed once. This is not a defense against a compromised local account
  or a previously authorized arbitrary-shell command that reaches that account.
* SSH is not an OS sandbox. Use dedicated least-privilege remote identities, no root login, no agent
  forwarding, no Docker/root-equivalent privileges unless deliberately authorized, and host-key verification.
* Named actions may still be dangerous. Their safety depends on administrator-supplied command text,
  binaries, shell initialization and remote environment. No regular-expression command blacklist is claimed.
* Receipt claiming is transactional. No exactly-once distributed-effects guarantee is possible here.
  A running receipt can mean in flight or crash-ambiguous; preserve its id and investigate. A completed
  error/timeout receipt also must not be interpreted as proof that no remote side effect occurred.
* Output buffers are bounded, and excessive output terminates the local process. There is no unlimited
  spill file. Plans/receipts have capacity limits that fail closed. Retention maintenance is manual in alpha;
  never delete receipts just to retry a destructive operation.
* State directories/files require 0700/0600. State includes raw commands and output needed for replay;
  it is private, not sanitized, not cryptographically immutable, and not safe to publish. Export only
  separately reviewed metadata. Root/controller owner can alter local records.
* Current controller scope: Linux/macOS. Remote Windows via OpenSSH is not yet validated. Public
  rate limiting, HA, cross-process concurrency policy, provider/ChatGPT integration and adversarial review
  remain release work. Operate one server process per state directory.

This candidate has no public vulnerability-reporting channel yet. Do not publish real credentials or
private deployment details in issues. Establish a maintainer contact before public release.
