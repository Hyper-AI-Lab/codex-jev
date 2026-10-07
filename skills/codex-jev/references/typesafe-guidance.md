# Pinned Guidance and Deliberate Adaptations

Adapted from TypeSafe's official skill at
[`65a39f393687675ce170e6094757de20370365b9`](https://github.com/typesafe-ai/skills/tree/65a39f393687675ce170e6094757de20370365b9)
and the per-item question patterns in `jev-code` at
[`c73c5762a7ea0e97c6cb2de0a973fbad22aeda93`](https://github.com/FrancoisChastel/jev-code/tree/c73c5762a7ea0e97c6cb2de0a973fbad22aeda93).
MIT notices are retained in [LICENSES.txt](LICENSES.txt).

Keep deterministic rules and execution in code. Ask narrow, independently useful
questions about enough evidence to answer them. Batch independent questions over
the same state, but do not assume one question sees another's answer. Question
IDs are application keys; the question itself must identify its evidence target.
Keep distributions rather than discarding uncertainty. Typed answers guarantee
an interface, not truth. Verify source coverage before interpreting an omission.

This integration deliberately does not adopt upstream automatic acceptance,
key-copying setup, 429 retries, multiple providers or model aliases. It retains
protected-file credentials, exact workspace sources, shared budgets, explicit
pages and advisory-only answers on pinned `jev-1.13.0`. It does not install the
upstream skill as a second broad system or load another lifecycle plugin.

During implementation changes check the relevant current primary contract:
[API](https://docs.typesafe.ai/api),
[retrieval](https://docs.typesafe.ai/cookbooks/rerank_typesafe),
[privacy](https://typesafe.ai/legal/privacy-policy).
These links are reference documentation, not permission for extra requests or
a promise of zero retention. No prompts or source text belong in usage reports.
