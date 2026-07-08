# Januscape — Linux KVM/x86 guest-to-host escape tracking site

Patch-status tracker for **Januscape** (**CVE-2026-53359**), a KVM/x86
guest-to-host escape in the Linux kernel.  A shadow-MMU role confusion —
`kvm_mmu_get_child_sp()` reuses a child shadow page without comparing its
role — leaves a stale rmap entry after a memslot is deleted, and a later
walk dereferences an `sptep` in the freed shadow page: a page
use-after-free the PoC turns into host code execution.  A hostile guest can
escape to host root; where `/dev/kvm` is world-accessible (the EL8+
default) an unprivileged local user can trigger it too.  Demonstrated on
both Intel and AMD.  Discovered by Hyunwoo Kim (`@v4bel`) and
[disclosed on 2026-07-06](https://thehackernews.com/2026/07/16-year-old-linux-kvm-flaw-lets-guest.html).
Public PoC: <https://github.com/V4bel/Januscape>.

The bug was introduced by `2032a93d66fa` in **v2.6.36** (2010) and fixed in
v7.2-rc1 by
[`81ccda30b4e8`](https://github.com/torvalds/linux/commit/81ccda30b4e83d8f5cc4fd50503c44e3a33abfeb)
(*KVM: x86: Fix shadow paging use-after-free due to unexpected role*).
Because it dates to 2.6.36, the practical exploitable window is **every
kernel from 2.6.36 through 7.1**; distro adoption of the backport is tracked
below.

**CVE-2026-53359** is assigned; the kernel CNA backported the fix to
6.1.177, 6.6.144, 6.12.95, 6.18.38, and 7.1.3, but each distribution has to
pick it up.  Januscape is **x86-only** (Intel and AMD); its **arm64
sibling** by the same researcher is **ITScape (CVE-2026-46316)**, a
KVM/arm64 vGIC-ITS escape tracked at <https://kimmo.cloud/itscape/>.

The rendered site is published at **<https://kimmo.cloud/januscape/>**.
Deployment plan and current setup state live in
[`WEBSITE.md`](WEBSITE.md).

## Source of truth

The tracker is a single Hugo page: [`site/content/_index.md`](site/content/_index.md).
Edit that file; everything else is build infrastructure.

## Local development

Requires Hugo extended (≥ 0.146.0) and Go (for Hugo Modules to fetch the
PaperMod theme).

### With Nix (recommended)

```sh
nix develop          # dev shell: hugo, go, git, resvg
cd site
hugo server          # local preview at http://localhost:1313/januscape/
```

If you use [direnv](https://direnv.net/), `direnv allow` once and the dev
shell auto-activates whenever you `cd` into the repo.

### Without Nix

Install Hugo extended ≥ 0.146.0 and Go ≥ 1.24 yourself, then:

```sh
cd site
hugo server          # http://localhost:1313/januscape/
```

## Build and publish

```sh
make build       # local build into site/public/
make dist        # build, then rsync to haig:/januscape/
make banner      # re-rasterise the social banner SVG → PNG (needs resvg + Roboto)
```

`make dist` runs `make build` first.  `make banner` is only needed after
editing `site/assets/januscape-tracker.svg`; the rendered PNG is committed.

## Repo layout

```
.
├── flake.nix              # Nix dev environment (hugo, go, git, resvg + RPM tools)
├── .envrc                 # direnv hook → `use flake`
├── .gitignore
├── Makefile               # `make build`, `make dist`, `make banner`
├── LICENSE                # CC BY 4.0
├── README.md              # this file
├── CLAUDE.md              # project instructions for Claude Code
├── WEBSITE.md             # publication plan / decisions log
├── scripts/               # auto-update agent: prompt + driver
├── systemd/               # user-level timer + service units
└── site/                  # Hugo project
    ├── hugo.toml
    ├── content/
    │   └── _index.md      # the tracker (single page)
    ├── assets/css/extended/custom.css   # PaperMod CSS overrides
    ├── assets/januscape-tracker.svg     # social-banner source (→ make banner)
    ├── static/januscape-tracker.png     # rendered OpenGraph banner (committed)
    ├── layouts/partials/  # PaperMod overrides (post_meta, extend_footer)
    ├── go.mod, go.sum     # Hugo Modules — pulls PaperMod theme
    └── …                  # standard Hugo skeleton
```

## License

[CC BY 4.0](LICENSE) — share and adapt with attribution.
