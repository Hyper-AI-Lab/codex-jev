# Attribution and Provenance

Codex Jev is an independent Hyper AI Lab project derived from James Cressler's
[Jev Codex Token Saver](https://github.com/jcressler/jev-codex-token-saver),
pinned at commit `1e1214bd7a1d7b2d3ee32bf1b8a88bbf9cd9d820`.
The upstream MIT license and copyright are retained verbatim in LICENSE.

Hyper AI Lab's changes add workspace authorization, local redaction, exact
evidence recovery, persistent budget accounting, quota recovery, reversible
installation, numeric measurements, portable packaging and safety tests.
Copyright (c) 2026 Hyper AI Lab for these additions, also under the MIT license.

This repository begins with a curated source export, not a copy of private
operational history. Legacy benchmark helpers remain for regression coverage;
historical network campaign commands are disabled. No private benchmark results,
credentials, conversation logs or deployment configuration are included.

Bundled dependencies have their own licenses. See THIRD_PARTY_NOTICES.txt and
the generated `dist/*.LEGAL.txt` files. `npm run licenses` regenerates notices
from the locked installed dependency tree.

Not affiliated with, endorsed by, or an official product of OpenAI or TypeSafe.
Codex and Jev are used descriptively; their names belong to their respective owners.

Typed question patterns and the packaged skill adapt MIT-licensed guidance from
TypeSafe AI's `typesafe-ai/skills` at `65a39f393687675ce170e6094757de20370365b9`
and Francois Chastel's `jev-code` at `c73c5762a7ea0e97c6cb2de0a973fbad22aeda93`.
Their copyright and permission notices are retained in
`skills/codex-jev/references/LICENSES.txt`. No upstream credential loader,
network client, installer, automatic acceptance policy or extra hook is installed.
