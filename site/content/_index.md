---
title: "Januscape — KVM guest-to-host escape tracking"
description: "Linux kernel KVM/x86 shadow-MMU use-after-free (CVE-2026-53359, Januscape) — guest-to-host escape — distro patch status tracker"
layout: "single"
date: 2026-07-08
lastmod: 2026-07-23
cover:
  image: "januscape-tracker.png"
  alt: "Januscape — Linux KVM/x86 shadow-MMU guest-to-host escape tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | CVE-2026-53359 |
| Alias | `Januscape` (the name its [PoC][poc] uses) |
| Component | Kernel: KVM/x86 shadow MMU — `kvm_mmu_get_child_sp()` role/`direct` confusion (`arch/x86/kvm/mmu/`) |
| Type | Guest-to-host escape / local privilege escalation — shadow-page role mismatch → stale rmap entry → page use-after-free |
| Impact | A malicious guest can execute code as **root on the host**; where `/dev/kvm` is world-accessible (the EL8+ default) an unprivileged **local** user can trigger the same bug to crash or take over the host. Intel **and** AMD x86 |
| Upstream fix | [`81ccda30b4e8`][fix] (*KVM: x86: Fix shadow paging use-after-free due to unexpected role*); first in **v7.2-rc1** |
| Introduced | [`2032a93d66fa`][intro] in **v2.6.36** (2010-08-01) — reachable for ~16 years |
| Affected window | Kernels **2.6.36 through 7.1** (every maintained tree without the backport); ≥ 7.2 fixed |
| Discoverer | Hyunwoo Kim ([`@v4bel`][poc]) |
| Public disclosure | 2026-07-06 |
| Public PoC | [V4bel/Januscape][poc] (demonstrates the host-crash path) |
| KEV / EPSS / CVSS | CVSS 7.8 Important (Red Hat CNA; NVD pending); EPSS 0.18 % (7th pct); not in KEV |
| Related | [ITScape (CVE-2026-46316)][itscape] — the arm64 sibling by the same researcher (KVM/arm64 vGIC-ITS escape). Januscape is x86-only; ITScape is arm64-only |

## How the exploitation chain works

Januscape is a use-after-free in KVM's **shadow MMU** — the software
page-table walker KVM uses when hardware two-dimensional paging (Intel EPT
/ AMD NPT) is not in play for a mapping, most notably for **nested**
guests. It is the same class of bug that [`0cb2af2ea66a`][prior] closed for
a mismatched *GFN*, reopened here through a mismatched *role*.

An attacker who controls a guest (or, locally, anyone who can open
`/dev/kvm`) changes a PDE mapping from outside the guest so that a region
backed by a 2 MiB shadow page (`kvm_mmu_page` with `direct=1`) is
re-walked as a 4 KiB mapping, which needs a `direct=0` page.
`kvm_mmu_get_child_sp()` compares the GFN but **not** the role, so it
reuses the existing `direct=1` page. A leaf SPTE installed on the new path
records an rmap entry under the walk-resolved GFN; but when that child is
zapped, `kvm_mmu_page_get_gfn()` recomputes the GFN as `sp->gfn + index`
(instead of consulting `shadowed_translation[]` / `gfns[]`), so it looks
under the wrong GFN and **fails to remove the rmap entry**.

Deleting the memslot then frees the shadow page while the rmap entry
survives. Any later walk of that GFN — dirty logging, an MMU-notifier
invalidation, and so on — dereferences an `sptep` inside the freed page: a
**use-after-free** the PoC turns into host code execution.

> :information_source: The vulnerable path is the **shadow** MMU, which on
> modern EPT/NPT hardware is exercised chiefly through **nested
> virtualization**. Disabling nested virt (`kvm_intel.nested=0` /
> `kvm_amd.nested=0`) removes the guest-driven path for untrusted guests.
> Two ways in exist: a hostile **guest** escaping to host root, and — where
> `/dev/kvm` is world-readable/writable (the default on EL8 and later) — an
> unprivileged **local** user reaching the same code directly. Restricting
> `/dev/kvm` closes the second without touching the first. **Only the
> kernel backport flips a verdict here**; nested-virt and `/dev/kvm` posture
> are mitigations recorded in prose, not columns.

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| [`2032a93d66fa`][intro] | Introduced | *KVM: MMU: Don't allocate gfns page for direct mmu pages* (v2.6.36) — direct shadow pages stopped carrying a `gfns[]` array, so `kvm_mmu_page_get_gfn()` recomputes the GFN as `sp->gfn + index` for them; combined with role-agnostic child reuse this yields the mismatch. |
| [`0cb2af2ea66a`][prior] | Partial fix | *KVM: x86: Fix shadow paging use-after-free due to unexpected GFN* — closed the GFN-mismatch variant but not the role-mismatch one. |
| [`81ccda30b4e8`][fix] | Fixed | *KVM: x86: Fix shadow paging use-after-free due to unexpected role* — compares the role before reusing a child shadow page; first released in **v7.2-rc1**. |

The reachable lifetime is therefore **v2.6.36 (2010) through v7.1**; ≥ 7.2
carries the fix. ARM64 KVM uses a different MMU and is **not affected** by
this bug — see [ITScape][itscape] for the arm64 escape.

## Upstream fixed versions

The fix reached Linus as **v7.2-rc1** and the kernel CNA (CVE-2026-53359)
backported it across every maintained stable line: **6.1.177**, **6.6.144**,
**6.12.95**, **6.18.38**, and **7.1.3**. 7.0.y reached end of life at 7.0.14
without the backport. The pre-6.1 longterm lines (5.15.y, 5.10.y) carry the
bug — the fix uses `sp->gfns[]` on those kernels — but have **not** received
a backport as of this writing.

| Branch | Status | Current | Notes |
|---|---|---|---|
| Linus mainline | :white_check_mark: Carries `81ccda30b4e8` | v7.2-rc4 | first fixed release v7.2-rc1 |
| 7.1.x | :white_check_mark: Carries the backport | 7.1.4 | first fixed point release |
| 7.0.x | :x: Not backported | 7.0.14 (EOL) | in window; end of life without the fix |
| 6.18.x | :white_check_mark: Carries the backport | 6.18.39 | LTS; first fixed point release |
| 6.12.x | :white_check_mark: Carries the backport | 6.12.96 | LTS; first fixed point release |
| 6.6.x | :white_check_mark: Carries the backport | 6.6.144 | LTS; first fixed point release |
| 6.1.x | :white_check_mark: Carries the backport | 6.1.177 | LTS; first fixed point release |
| 5.15.x | :x: Not backported | 5.15.211 | in window; no backport yet |
| 5.10.x | :x: Not backported | 5.10.260 | in window; no backport yet |

When verifying a tree directly, the fixed function is
`kvm_mmu_get_child_sp()` in `arch/x86/kvm/mmu/mmu.c`; the fix adds a role
comparison before reusing an existing child shadow page.

## Distribution status

The deciding fact per release is whether the **kernel** carries the
[`81ccda30b4e8`][fix] backport. Because the bug dates to v2.6.36, **every**
current distro kernel is inside the affected window — there are no
"predates the bug" rows here — so a release is `:x:` until it ships the
fix. `/dev/kvm` exposure and nested-virt defaults change *who* can reach
the bug, not whether the kernel is fixed; they are recorded in prose.
*Fixed since* records the date the kernel fix first lands in that release.

The rows below track a focused set of x86-64 distributions. Other EL10
-family systems (RHEL 10, CentOS Stream 10, Oracle Linux 10, CloudLinux
OS 10) beyond the Rocky/AlmaLinux row, and other systems named in the
disclosures, appear only in prose where relevant.

| Distribution | Release | Kernel | Fixed since | Status |
|---|---|---|---|---|
| Debian | sid (unstable) | 7.1.3-1 | 2026-07-05 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.3-1 | 2026-07-04 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.95-1 | 2026-07-05 | :white_check_mark: Fixed |
| Debian | 12 (bookworm) | 6.1.177-1 | 2026-07-17 | :white_check_mark: Fixed |
| Debian | 11 (bullseye, LTS) | 5.10.223-1 | — | :x: Vulnerable — 5.10.y not backported upstream |
| Proxmox VE | 9 | 7.0.14-4-pve | 2026-07-08 | :white_check_mark: Fixed |
| Proxmox VE | 8 | 6.8.12-33-pve | 2026-07-08 | :white_check_mark: Fixed |
| NixOS | Unstable | 6.18.38 | 2026-07-08 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.38 | 2026-07-08 | :white_check_mark: Fixed |
| Rocky Linux | 10 | 6.12.0-211.32.1.el10_2 | 2026-07-13 | :white_check_mark: Fixed (RLSA rebuild of RHSA-2026:36956) |
| Rocky Linux | 9 | 5.14.0-687.24.1.el9_8 | 2026-07-13 | :white_check_mark: Fixed (RLSA rebuild of RHSA-2026:36957) |
| Rocky Linux | 8 | 4.18.0-553.144.1.el8_10 | 2026-07-15 | :white_check_mark: Fixed (RLSA-2026:39179) |
| Amazon Linux | 2023 (kernel 6.1) | 6.1.176-220.360 | — | :x: Vulnerable — in-window, no ALAS |
| Amazon Linux | 2023 (kernel6.12) | 6.12.94-123.190 | 2026-07-20 | :white_check_mark: Fixed (ALAS2023-2026-1970) |
| Amazon Linux | 2023 (kernel6.18) | 6.18.38-73.137 | 2026-07-20 | :white_check_mark: Fixed (ALAS2023-2026-1969) |
| Amazon Linux | 2 (kernel 4.14) | 4.14.355-284.737 | — | :x: Vulnerable — no fix expected (AL2 EOL 2026-06-30) |
| Amazon Linux | 2 (kernel-5.10) | 5.10.259-258.1043 | — | :x: Vulnerable — no fix expected (AL2 EOL 2026-06-30) |
| Amazon Linux | 2 (kernel-5.15) | 5.15.210-148.245 | — | :x: Vulnerable — no fix expected (AL2 EOL 2026-06-30) |
{.distros}

### Debian

Debian's `linux` is affected in every suite (the bug predates all of
them). **sid** shipped `linux 7.1.3-1`, which tracks upstream 7.1.3 and
carries the backport — sid is fixed. **forky** (testing) migrated from
7.0.y to `linux 7.1.3-1`, which carries the backport — forky is fixed.
**trixie** shipped `linux 6.12.95-1` via `trixie-security` (2026-07-05),
tracking upstream 6.12.95 which carries the backport — trixie is fixed.
**bookworm** shipped `linux 6.1.177-1` via `bookworm-security`
(2026-07-17), carrying the backport — bookworm is fixed. **bullseye**
(5.10.223-1) has no upstream backport for 5.10.y yet, so it remains
vulnerable until Debian ships the fix.
Debian keeps `/dev/kvm` owned `root:kvm` mode `0660`, so the
unprivileged *local* vector needs `kvm`-group membership there; the
guest-escape vector is unaffected by that.

### Proxmox VE

Proxmox ships its own Proxmox-built kernels (`proxmox-kernel-*`), so
Debian's fix status does not carry over. Proxmox released fixed kernels
for both supported series on 2026-07-08: `proxmox-kernel-6.8.12-33-pve`
(PVE 8 default series) and `proxmox-kernel-7.0.14-4-pve` (the PVE 9
default as of `proxmox-default-kernel` 2.1.0), both now in the
`pve-no-subscription` repository. The 6.17 series fix
(`proxmox-kernel-6.17.13-15-pve`) subsequently shipped to
`pve-no-subscription` as well (advisory PSA-2026-00027-1); PVE 9 systems
running the 6.17 kernel are now covered. The opt-in
`proxmox-kernel-6.14` (`bpo12`) series for PVE 8 has not received a
Januscape cherry-pick; its latest release (`6.14.11-9~bpo12+1`,
2026-05-15) predates the disclosure, leaving PVE 8 systems using this
opt-in kernel vulnerable. The opt-in `proxmox-kernel-6.14` (trixie)
series for PVE 9 is in the same position: latest `6.14.11-9-pve`
(2026-05-15) carries no Januscape cherry-pick, leaving PVE 9 systems
on this opt-in kernel vulnerable. Proxmox publishes kernel updates
to `pve-no-subscription` first; the enterprise repository receives the
same kernels later. Proxmox VE is x86-only, so it does not appear in the
[ITScape][itscape] (arm64) tracker.

### Rocky Linux / RHEL family

The EL family ships `/dev/kvm` **world-accessible** by default (EL8 and
later), so on those hosts *any* local user — not just a guest — can reach
the bug; combined with the guest-escape path this is the higher-exposure
case. Red Hat shipped RHSA-2026:36957 (RHEL 9, fixed kernel
`5.14.0-687.24.1.el9_8`) and RHSA-2026:36956 (RHEL 10, fixed kernel
`6.12.0-211.32.1.el10_2`); Rocky 9 and Rocky 10 have now rebuilt those
NVRs and are fixed. RHSA-2026:37729 additionally shipped for RHEL 9.4
Update Services for SAP Solutions (fixed kernel
`5.14.0-427.137.1.el9_4`), and RHSA-2026:38902 for RHEL 9.6 EUS
(fixed kernel `5.14.0-570.127.1.el9_6`). RHSA-2026:39083 shipped for
RHEL 8 on 2026-07-14 (fixed kernel `4.18.0-553.143.1.el8_10`); AlmaLinux 8
rebuilt as ALSA-2026:39083. RHSA-2026:39082 additionally shipped for RHEL 8
NFV on 2026-07-14 (fixed real-time kernel
`4.18.0-553.143.1.rt7.484.el8_10`). Rocky 8 rebuilt as RLSA-2026:39179 (kernel
`4.18.0-553.144.1.el8_10`, issued 2026-07-15); this build supersedes
553.143.1 and carries the backport. RHSA-2026:40082 additionally shipped for
RHEL 9.2 Update Services for SAP Solutions (fixed kernel
`5.14.0-284.181.1.el9_2`), and RHSA-2026:39371 for RHEL 10.0 EUS (fixed
kernel `6.12.0-55.88.1.el10_0`). RHSA-2026:41229 additionally shipped for
RHEL 8.8 Telecommunications Update Service and Update Services for SAP
Solutions on 2026-07-17 (fixed kernel `4.18.0-477.154.1.el8_8`). Oracle
Linux 10 and CloudLinux OS 10 are expected to track the RHEL fixes.

### Amazon Linux

AL2023's opt-in kernel6.18 and kernel6.12 streams have received fixes.
Amazon shipped ALAS2023-2026-1969 (2026-07-20) for kernel6.18,
fixing CVE-2026-53359 in `kernel6.18-6.18.38-73.137.amzn2023`; upstream
6.18.38 carries the backport. Amazon shipped ALAS2023-2026-1970
(2026-07-20) for kernel6.12, fixing CVE-2026-53359 via a cherry-pick into
`kernel6.12-6.12.94-123.190.amzn2023`. The AL2023 **default 6.1 stream**
(`kernel`) has not received an ALAS for this CVE and remains vulnerable.
**AL2**, however, reached end of support on **2026-06-30**: AWS no longer
provides security updates or bug fixes for AL2 core packages, so its
three streams (4.14, plus 5.10 / 5.15 via `amazon-linux-extras`) are not
expected to ever receive a fix — the exit for an AL2 KVM host is
migrating to AL2023 or another patched distribution.

## Detection

**Is the running kernel in the affected window and missing the fix?**
Compare the running kernel against the *Upstream fixed versions* table and
your distro row above:

```bash
uname -r
```

**Is this an x86 host?**  Januscape is x86-only (Intel or AMD); arm64 hosts
are not affected by this bug:

```bash
uname -m
```

**Is KVM in use, and is nested virtualization enabled?**  The shadow-MMU
path is reached chiefly through nested guests; `Y` means nested virt is on:

```bash
cat /sys/module/kvm_intel/parameters/nested
```

On AMD hosts check the AMD module instead:

```bash
cat /sys/module/kvm_amd/parameters/nested
```

**Who can open `/dev/kvm`?**  World access (e.g. `crw-rw-rw-`, the EL8+
default) exposes the local unprivileged vector; `crw-rw----` root:kvm
limits it to the `kvm` group:

```bash
ls -l /dev/kvm
```

## Public PoC

The upstream PoC is in [V4bel/Januscape][poc]; the published exploit
demonstrates the host-crash path and is reported to reach root on both
Intel and AMD. Do **not** run it on a system you are not authorised to
test.

## Mitigation

The real fix is a patched kernel (the `81ccda30b4e8` backport). Until one
is installed, two interim measures each narrow the exposure.

### Disable nested virtualization (removes the guest-driven path)

On an Intel host, turn nested virt off and reload the module (no running
nested guests):

```bash
sudo modprobe -r kvm_intel
```

```bash
echo 'options kvm_intel nested=0' | sudo tee /etc/modprobe.d/99-januscape.conf
```

On an AMD host use `kvm_amd` in both commands. This blocks the shadow-MMU
path for untrusted guests but does not close the hole for a workload that
legitimately needs nested virtualization.

### Restrict `/dev/kvm` (removes the unprivileged local vector)

Where `/dev/kvm` is world-accessible (EL8+), restrict it to a trusted
group so unprivileged local users cannot open it directly:

```bash
sudo chmod 0660 /dev/kvm
```

Persist it with a udev rule:

```bash
echo 'KERNEL=="kvm", GROUP="kvm", MODE="0660"' | sudo tee /etc/udev/rules.d/65-kvm.rules
```

This does **not** stop a hostile guest escaping — it only removes the
local unprivileged path. Neither measure is a fix; the kernel hole remains
until patched.

## Risk notes

- **Multi-tenant / untrusted-guest hosts:** this is a guest-to-host-root
  primitive from inside an otherwise isolated VM — the headline risk for
  anyone running untrusted guests with nested virtualization enabled.
- **EL8+ hosts (`/dev/kvm` world-accessible):** any unprivileged local
  user can reach the bug directly, without needing a guest — self-hosted CI
  and shared multi-user hosts are directly in scope.
- **Intel and AMD both:** unlike many KVM escapes this is demonstrated on
  both vendors; there is no "AMD is safe" caveat.
- **Backports available (CVE-2026-53359):** the fix has landed in 6.1.177,
  6.6.144, 6.12.95, 6.18.38, and 7.1.3, but distro kernels that have not
  yet adopted one of those releases remain vulnerable. Check the
  distribution row for your kernel.

## Verification log

*Last verified 2026-07-23.*

### Upstream

- The fix is `81ccda30b4e8` (*KVM: x86: Fix shadow paging use-after-free
  due to unexpected role*), first released in **v7.2-rc1**. It compares the
  role before `kvm_mmu_get_child_sp()` reuses a child shadow page.
- The bug was introduced by `2032a93d66fa` in **v2.6.36**; the prior
  partial fix `0cb2af2ea66a` closed only the GFN-mismatch variant.
- **CVE-2026-53359** assigned by the kernel CNA (confirmed via `vulns.git`
  `origin/master`; record keys on `81ccda30b4e8`). The `.dyad` gives the
  per-branch fixed versions used in the *Upstream fixed versions* table.
- **Stable backports landed** (confirmed by SHA-reference grep against
  `~/src/linux/stable`): 6.1.177 (`b1337aae5e19`), 6.6.144
  (`9291654d69e0`), 6.12.95 (`2ad3afa40ac6`), 6.18.38 (`5e470998a23e`),
  and 7.1.3 (`1ae7d5a6db6c`). 7.0.y is EOL at 7.0.14 without the fix;
  5.15.y and 5.10.y are in-window and not yet backported.

### Scoring

- Red Hat CNA assigned **CVSSv3 7.8 Important**
  (CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H, verified); NVD
  status still "Received" (no NVD score yet). EPSS 0.18 % (7th
  percentile, via api.first.org). Not in CISA KEV.

### Distributions

- **Debian** (via Debian security tracker JSON + snapshot.debian.org):
  unstable `7.1.3-1`, testing (forky) `7.1.3-1` (first seen in snapshot
  2026-07-04), stable (trixie) `6.12.95-1` (DSA-6381-1, via
  `trixie-security`, first seen 2026-07-05), and oldstable (bookworm)
  `6.1.177-1` (via `bookworm-security`, first seen in snapshot
  2026-07-17; Debian security tracker now resolved) all carry the
  backport → fixed. Oldoldstable (bullseye) `5.10.223-1` (5.10.y
  unpatched upstream) remains vulnerable.
- **Proxmox VE**: Proxmox shipped fixed kernels on 2026-07-08 (confirmed
  in the `pve-no-subscription` repo via the Proxmox forum thread). PVE 8
  default kernel `proxmox-kernel-6.8.12-33-pve` and PVE 9 default kernel
  `proxmox-kernel-7.0.14-4-pve` (the default since `proxmox-default-kernel`
  2.1.0) both carry the backport → `:white_check_mark:`. The 6.17 series fix
  `proxmox-kernel-6.17.13-15-pve` subsequently landed in
  `pve-no-subscription` (advisory PSA-2026-00027-1); confirmed in Packages.gz.
  Opt-in 6.14 `bpo12` series for PVE 8 (via `origin/bookworm-6.14`
  changelog): latest `6.14.11-9~bpo12+1` (2026-05-15) carries no Januscape
  cherry-pick → PVE 8 systems on this opt-in remain `:x:`. Opt-in 6.14
  trixie series for PVE 9 (via `origin/trixie-6.14` changelog): latest
  `6.14.11-9-pve` (2026-05-15) carries no Januscape cherry-pick → PVE 9
  systems on this opt-in also remain `:x:`.
- **NixOS** (via the local nixpkgs clone): the default `linuxPackages`
  (`linux_6_18`) is `6.18.38` on both nixos-unstable and nixos-26.05, and
  `linuxPackages_latest` (`linux_7_1`) is `7.1.3` — both carry the backport
  → fixed.
- **Rocky / RHEL family**: RHSA-2026:36957 (RHEL 9, fixed NVR
  `5.14.0-687.24.1.el9_8`) and RHSA-2026:36956 (RHEL 10, fixed NVR
  `6.12.0-211.32.1.el10_2`) published (via Red Hat security API).
  AlmaLinux rebuilt both on 2026-07-10 (via errata.almalinux.org):
  ALSA-2026:36957 (AL9, `5.14.0-687.24.1.el9_8`) and ALSA-2026:36956
  (AL10, `6.12.0-211.32.1.el10_2`). Rocky 9 BaseOS ships
  `5.14.0-687.24.1.el9_8` (confirmed via Rocky 9 BaseOS repodata) →
  `:white_check_mark:`. Rocky 10 BaseOS ships `6.12.0-211.32.1.el10_2`
  (confirmed via Rocky 10 BaseOS repodata) → `:white_check_mark:`.
  RHSA-2026:37729 additionally shipped for RHEL 9.4 EUS
  (`5.14.0-427.137.1.el9_4`), and RHSA-2026:38902 for RHEL 9.6 EUS
  (`5.14.0-570.127.1.el9_6`); neither reflected in the Rocky 9 row,
  which tracks the main RHEL 9.x release. RHSA-2026:40082 shipped for
  RHEL 9.2 E4S (`5.14.0-284.181.1.el9_2`), and RHSA-2026:39371 for
  RHEL 10.0 EUS (`6.12.0-55.88.1.el10_0`) (via Red Hat security API).
  RHSA-2026:41229 shipped for RHEL 8.8 TUS and SAP Solutions
  (`4.18.0-477.154.1.el8_8`, 2026-07-17; via Red Hat security API).
  RHSA-2026:39083 shipped for RHEL 8 on 2026-07-14 (fixed NVR
  `4.18.0-553.143.1.el8_10`, via Red Hat security API); AlmaLinux 8
  rebuilt as ALSA-2026:39083 (via errata.almalinux.org).
  RHSA-2026:39082 additionally shipped for RHEL 8 NFV on 2026-07-14
  (fixed real-time kernel NVR `4.18.0-553.143.1.rt7.484.el8_10`, via
  Red Hat security API). Rocky 8 BaseOS
  ships `4.18.0-553.144.1.el8_10` via RLSA-2026:39179 (confirmed via
  Rocky 8 BaseOS repodata + updateinfo); this build supersedes 553.143.1
  and carries the backport → `:white_check_mark:`.
- **Amazon Linux** (via repodata `updateinfo.xml.gz`): ALAS2023-2026-1969
  (issued 2026-07-20) fixes CVE-2026-53359 in `kernel6.18-6.18.38-73.137`
  (upstream 6.18.38 carries the backport) → AL2023 kernel6.18 now
  `:white_check_mark:`. ALAS2023-2026-1970 (issued 2026-07-20) fixes
  CVE-2026-53359 via cherry-pick in `kernel6.12-6.12.94-123.190` → AL2023
  kernel6.12 now `:white_check_mark:`. AL2023 core (kernel 6.1) has no
  ALAS for CVE-2026-53359 → `:x:`. **AL2 reached end of support on
  2026-06-30** (per the AWS AL2 FAQ; confirmed against endoflife.date)
  without an ALAS for this CVE — its three rows are marked "no fix
  expected" and will not flip.

## References

| Source | URL |
|---|---|
| Public PoC (V4bel) | <https://github.com/V4bel/Januscape> |
| Companion tracker — ITScape (arm64) | <https://kimmo.cloud/itscape/> |
| Kernel fix | <https://github.com/torvalds/linux/commit/81ccda30b4e83d8f5cc4fd50503c44e3a33abfeb> |
| Prior partial fix (GFN variant) | <https://github.com/torvalds/linux/commit/0cb2af2ea66ad8ff195c156ea690f11216285bdf> |
| CVE-2026-53359 | <https://www.cve.org/CVERecord?id=CVE-2026-53359> |
| CloudLinux advisory | <https://blog.cloudlinux.com/januscape-cve-2026-53359-mitigation-and-kernel-update-on-cloudlinux/> |
| The Hacker News writeup | <https://thehackernews.com/2026/07/16-year-old-linux-kvm-flaw-lets-guest.html> |
| Proxmox forum thread | <https://forum.proxmox.com/threads/are-there-mitigations-available-for-cve-2026-53359-januscape.184874/> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-53359> |
| Debian package madison (dak-backed) | <https://api.ftp-master.debian.org/madison?package=linux&s=sid,forky,trixie,bookworm,bullseye&text=on> |
| AlmaLinux errata | <https://errata.almalinux.org/> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
{.references}

[poc]: https://github.com/V4bel/Januscape
[itscape]: https://kimmo.cloud/itscape/
[fix]: https://github.com/torvalds/linux/commit/81ccda30b4e83d8f5cc4fd50503c44e3a33abfeb
[intro]: https://github.com/torvalds/linux/commit/2032a93d66fa282ba0f2ea9152eeff9511fa9a96
[prior]: https://github.com/torvalds/linux/commit/0cb2af2ea66ad8ff195c156ea690f11216285bdf
