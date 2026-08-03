---
title: "Januscape — KVM guest-to-host escape"
description: "Linux kernel KVM/x86 shadow-MMU use-after-free (CVE-2026-53359, Januscape) — guest-to-host escape — distro patch status tracker"
layout: "single"
date: 2026-07-08
lastmod: 2026-08-03
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
| KEV / EPSS / CVSS | CVSS 7.8 Important (Red Hat CNA), 8.8 HIGH (NVD CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H); EPSS 0.91 % (56th pct); not in KEV |
| Related | [ITScape (CVE-2026-46316)][itscape] — the arm64 sibling by the same researcher (KVM/arm64 vGIC-ITS escape). Januscape is x86-only; ITScape is arm64-only |
{.summary}

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

## Patch status

The deciding fact per row is whether the **kernel** carries the
[`81ccda30b4e8`][fix] backport. Because the bug dates to v2.6.36,
**every** kernel below is inside the affected window — there are no
"predates the bug" rows here — so a row is `:x:` until its kernel ships
the fix. `/dev/kvm` exposure and nested-virt defaults change *who* can
reach the bug, not whether the kernel is fixed; they are recorded in
prose.

The first group tracks the upstream kernel itself; the rest are a
focused set of x86-64 distributions (other EL10-family systems — RHEL
10, CentOS Stream 10, Oracle Linux 10, CloudLinux OS 10 — and other
systems named in the disclosures appear only in prose). *Current
kernel* is the latest version observed in the row's user-facing
channel; *First fixed* is the first release or build carrying the fix,
and *Fixed since* the date it first held (both stay `—` while a row is
vulnerable).

| Distribution | Release | Current kernel | First fixed | Fixed since | Status |
|---|---|---|---|---|---|
| Linux kernel | mainline | 7.2-rc6 | 7.2-rc1 | 2026-06-28 | :white_check_mark: Fixed — carries `81ccda30b4e8` |
| Linux kernel | 7.1.x | 7.1.5 | 7.1.3 | 2026-07-04 | :white_check_mark: Fixed |
| Linux kernel | 7.0.x | 7.0.14 | — | — | :x: Vulnerable — EOL without the fix |
| Linux kernel | 6.18.x | 6.18.41 | 6.18.38 | 2026-07-04 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.100 | 6.12.95 | 2026-07-04 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.147 | 6.6.144 | 2026-07-04 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.180 | 6.1.177 | 2026-07-04 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.15.x | 5.15.213 | — | — | :x: Vulnerable — LTS, no backport yet |
| Linux kernel | 5.10.x | 5.10.262 | — | — | :x: Vulnerable — LTS, no backport yet |
| Debian | sid (unstable) | 7.1.5-1 | 7.1.3-1 | 2026-07-05 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.3-1 | 7.1.3-1 | 2026-07-04 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.100-1 | 6.12.95-1 | 2026-07-05 | :white_check_mark: Fixed — DSA-6381-1 |
| Debian | 12 (bookworm) | 6.1.177-1 | 6.1.177-1 | 2026-07-17 | :white_check_mark: Fixed — DLA-4688-1 |
| Debian | 11 (bullseye, LTS) | 5.10.259-1 | — | — | :x: Vulnerable — no backport in 5.10.x |
| Debian | 11 (linux-6.1 opt-in) | 6.1.177-1~deb11u1 | 6.1.177-1~deb11u1 | 2026-07-25 | :white_check_mark: Fixed — DLA-4700-1 |
| Proxmox VE | 9 (default) | 7.0.14-8-pve | 7.0.14-4-pve | 2026-07-08 | :white_check_mark: Fixed |
| Proxmox VE | 9 (6.17 old) | 6.17.13-21-pve | 6.17.13-15-pve | 2026-07-11 | :white_check_mark: Fixed — PSA-2026-00027-1 |
| Proxmox VE | 9 (6.14 old) | 6.14.11-9-pve | — | — | :x: Vulnerable — no cherry-pick |
| Proxmox VE | 8 (default) | 6.8.12-39-pve | 6.8.12-33-pve | 2026-07-08 | :white_check_mark: Fixed |
| Proxmox VE | 8 (6.14 opt-in) | 6.14.11-9-bpo12-pve | — | — | :x: Vulnerable — no cherry-pick |
| Proxmox VE | 8 (6.11 old) | 6.11.11-2-pve | — | — | :x: Vulnerable — no cherry-pick |
| NixOS | Unstable | 6.18.41 | 6.18.38 | 2026-07-08 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.41 | 6.18.38 | 2026-07-08 | :white_check_mark: Fixed |
| Rocky Linux | 10 | 6.12.0-211.42.1.el10_2 | 6.12.0-211.32.1.el10_2 | 2026-07-13 | :white_check_mark: Fixed — RLSA rebuild of RHSA-2026:36956 |
| Rocky Linux | 9 | 5.14.0-687.33.1.el9_8 | 5.14.0-687.24.1.el9_8 | 2026-07-13 | :white_check_mark: Fixed — RLSA rebuild of RHSA-2026:36957 |
| Rocky Linux | 8 | 4.18.0-553.148.1.el8_10 | 4.18.0-553.144.1.el8_10 | 2026-07-15 | :white_check_mark: Fixed — RLSA-2026:39179 |
| Amazon Linux | 2023 (default) | 6.1.176-223.369 | 6.1.176-221.367 | 2026-07-24 | :white_check_mark: Fixed — ALAS2023-2026-2001 |
| Amazon Linux | 2023 (kernel6.12) | 6.12.94-123.192 | 6.12.94-123.190 | 2026-07-20 | :white_check_mark: Fixed — ALAS2023-2026-1970 |
| Amazon Linux | 2023 (kernel6.18) | 6.18.38-76.139 | 6.18.38-73.137 | 2026-07-20 | :white_check_mark: Fixed — ALAS2023-2026-1969 |
{.distros}

### Linux kernel

The fix reached Linus as **v7.2-rc1** and the kernel CNA
(CVE-2026-53359) backported it across the maintained stable lines on
2026-07-04. 7.0.y reached end of life at 7.0.14 without the backport.
The pre-6.1 longterm lines (5.15.y, 5.10.y) carry the bug — the fix
uses `sp->gfns[]` on those kernels — but have **not** received a
backport as of this writing.

When verifying a tree directly, the fixed function is
`kvm_mmu_get_child_sp()` in `arch/x86/kvm/mmu/mmu.c`; the fix adds a
role comparison before reusing an existing child shadow page.

### Debian

Debian's `linux` is affected in every suite (the bug predates all of
them); the security tracker's CVE-2026-53359 record drove these
assessments. **bullseye** (LTS) default `linux` kernel (`5.10.x` series) has not
received the fix — upstream 5.10.y carries no backport and Debian has
not issued an independent cherry-pick; `5.10.259-1` in
`bullseye-security` remains vulnerable. The opt-in `linux-6.1` package
(bookworm's 6.1 kernel rebuilt for bullseye) was updated to
`6.1.177-1~deb11u1` in `bullseye-security` (2026-07-25), carrying the
fix via the upstream 6.1.177 release. Debian keeps `/dev/kvm` owned
`root:kvm` mode `0660`, so the unprivileged *local* vector needs
`kvm`-group membership there; the guest-escape vector is unaffected by
that.

### Proxmox VE

Proxmox ships its own Proxmox-built kernels (`proxmox-kernel-*`), so
Debian's fix status does not carry over. Each PVE release's default
kernel series (pinned by `proxmox-default-kernel`) and its other
offered series get their own rows above: both defaults (the 7.0 series
on PVE 9, 6.8 on PVE 8) were fixed on 2026-07-08, the 6.17 series
followed with advisory PSA-2026-00027-1,
and the 6.11 and 6.14 series have had no release since before the
disclosure, so they carry no Januscape cherry-pick. Proxmox
publishes kernel updates to `pve-no-subscription` first; the enterprise
repository receives the same kernels later. Proxmox VE is x86-only, so
it does not appear in the [ITScape][itscape] (arm64) tracker.

An *opt-in* series is Proxmox's preview of a likely next default,
aimed at setups that need newer hardware support; an *old* series is
one the release has moved past — a superseded default (PVE 9's 6.17
and 6.14) or an opt-in overtaken by a newer one (PVE 8's 6.11).
Proxmox discontinues updates for superseded series once a short
transition tail ends (the 6.17 fix above landed inside that tail),
and every such PVE kernel series is long end-of-life on kernel.org,
so a fix can only ever arrive as a Proxmox cherry-pick. A vulnerable
*old* row is therefore unlikely ever to flip — the exit is rebooting
into the release's current default kernel.

### Rocky Linux / RHEL family

The EL family ships `/dev/kvm` **world-accessible** by default (EL8 and
later), so on those hosts *any* local user — not just a guest — can
reach the bug; combined with the guest-escape path this is the
higher-exposure case. RHEL-family kernels carry security backports
without moving their upstream base version, so the version string alone
cannot confirm a fix — the signal is an erratum. The fix flowed RHEL →
AlmaLinux → Rocky:

- **Standard `kernel`, EL10 / EL9** — Red Hat shipped
  **RHSA-2026:36956** (RHEL 10, kernel `6.12.0-211.32.1.el10_2`) and
  **RHSA-2026:36957** (RHEL 9, kernel `5.14.0-687.24.1.el9_8`);
  AlmaLinux rebuilt both on 2026-07-10, and Rocky 10 / Rocky 9 rebuilt
  the same NVRs (table above).
- **Standard `kernel`, EL8** — Red Hat shipped **RHSA-2026:39083**
  (2026-07-14, kernel `4.18.0-553.143.1.el8_10`); AlmaLinux 8 rebuilt
  it as **ALSA-2026:39083**. Rocky 8 shipped the superseding cumulative
  `4.18.0-553.144.1.el8_10` as **RLSA-2026:39179** (2026-07-15), which
  carries the backport.
- **Real-time kernels** (no table rows — a niche variant) —
  **RHSA-2026:39983** (RHEL 9.2 E4S NFV, `kernel-rt
  5.14.0-284.181.1.rt14.466.el9_2`, 2026-07-15) and **RHSA-2026:39082**
  (RHEL 8 NFV, `kernel-rt 4.18.0-553.143.1.rt7.484.el8_10`,
  2026-07-14).
- **EUS / E4S / TUS streams** (no table rows — the Rocky rows track the
  main RHEL releases) — **RHSA-2026:39371** (RHEL 10.0 EUS,
  `6.12.0-55.88.1.el10_0`), **RHSA-2026:38902** (RHEL 9.6 EUS,
  `5.14.0-570.127.1.el9_6`), **RHSA-2026:37729** (RHEL 9.4 SAP US,
  `5.14.0-427.137.1.el9_4`), **RHSA-2026:40082** (RHEL 9.2 SAP US,
  `5.14.0-284.181.1.el9_2`), **RHSA-2026:41229** (RHEL 8.8
  TUS / SAP US, `4.18.0-477.154.1.el8_8`, 2026-07-17), and
  **RHSA-2026:49033** (RHEL 8.6 AUS / EUS Long-Life,
  `4.18.0-372.204.1.el8_6`, 2026-07-31).

Oracle Linux 10 and CloudLinux OS 10 are expected to track the RHEL
fixes.

### Amazon Linux

Each **AL2023** kernel stream is its own row above; status is verified
from the repodata `updateinfo.xml` (the per-CVE ALAS pages are
JS-rendered and don't fetch headlessly). The default stream (the plain
`kernel` package, a 6.1 series) and `kernel6.12` fixes are Amazon
cherry-picks — their fixed builds sit below the upstream first-fixed
releases — while `kernel6.18`'s fixed build tracks upstream 6.18.38.

**AL2** (amzn2) is not tracked here: it reached end of support on
**2026-06-30** — before this tracker existed — with no ALAS ever issued
for this CVE, and AWS no longer provides security updates or bug fixes
for AL2 core packages. All three of its kernel streams (4.14, plus
5.10 / 5.15 via `amazon-linux-extras`) are in-window and permanently
vulnerable, and no fix is expected. The exit for an AL2 KVM host is
migrating to AL2023 (or another patched distribution).

## Detection

**Is the running kernel in the affected window and missing the fix?**
Compare the running kernel against the *Patch status* table above — the
*Linux kernel* rows for the upstream point releases, and your
distribution's row:

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
- **Backports available (CVE-2026-53359):** the fix has landed in 7.1.3,
  6.18.38, 6.12.95, 6.6.144, and 6.1.177, but distro kernels that have not
  yet adopted one of those releases remain vulnerable. Check the
  distribution row for your kernel.

## Verification log

Every verdict in the table above is backed by a checkable source. This
log records the provenance — the advisory, repository index, or git
reference that established each fact — so any row can be audited or
reproduced. Most readers never need it.

{{< details summary="Full verification log" >}}
#### Upstream

- The fix is `81ccda30b4e8` (*KVM: x86: Fix shadow paging use-after-free
  due to unexpected role*), first released in **v7.2-rc1**. It compares the
  role before `kvm_mmu_get_child_sp()` reuses a child shadow page.
- The bug was introduced by `2032a93d66fa` in **v2.6.36**; the prior
  partial fix `0cb2af2ea66a` closed only the GFN-mismatch variant.
- **CVE-2026-53359** assigned by the kernel CNA (confirmed via `vulns.git`
  `origin/master`; record keys on `81ccda30b4e8`). The `.dyad` gives the
  per-branch fixed versions used in the `Linux kernel` rows of the
  *Patch status* table.
- **Stable backports** (confirmed by SHA-reference grep against
  `~/src/linux/stable`):
  - Landed in 7.1.3 (`1ae7d5a6db6c`), 6.18.38 (`5e470998a23e`), 6.12.95
    (`2ad3afa40ac6`), 6.6.144 (`9291654d69e0`), and 6.1.177
    (`b1337aae5e19`).
  - 7.0.y is EOL at 7.0.14 without the fix; 5.15.y and 5.10.y are
    in-window and not yet backported.

#### Scoring

- Red Hat CNA assigned **CVSSv3 7.8 Important**
  (CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H); NVD published
  **8.8 HIGH** (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H, via
  NVD API). EPSS 0.91 % (56th percentile, via api.first.org). Not in
  CISA KEV.

#### Distributions

- **Debian** (via Debian security tracker JSON + snapshot.debian.org):
  - unstable/sid — `7.1.3-1` carries the backport — fixed.
  - testing/forky — `7.1.3-1` (first seen in snapshot 2026-07-04) —
    fixed.
  - stable/trixie — `6.12.95-1` (DSA-6381-1, via `trixie-security`,
    first seen 2026-07-05) — fixed.
  - oldstable/bookworm — `6.1.177-1` (DLA-4688-1, via `bookworm-security`,
    first seen in snapshot 2026-07-17) — fixed.
  - LTS/bullseye default kernel — `5.10.259-1` in `bullseye-security`
    (via Debian security tracker JSON) carries no Januscape
    cherry-pick; upstream 5.10.y has not received the backport —
    vulnerable.
  - LTS/bullseye opt-in `linux-6.1` — updated to
    `6.1.177-1~deb11u1` in `bullseye-security` (DLA-4700-1, first seen
    snapshot 2026-07-25); 6.1.177 is the first upstream fixed release — fixed.
- **Proxmox VE** (fixed kernels confirmed in the `pve-no-subscription`
  repo via the Proxmox forum thread and Packages.gz; opt-in series via
  the pve-kernel changelogs):
  - PVE 9 default — `proxmox-kernel-7.0.14-4-pve` (the default since
    `proxmox-default-kernel` 2.1.0) carries the backport, shipped
    2026-07-08 — fixed.
  - PVE 9 old 6.17 — the fix `proxmox-kernel-6.17.13-15-pve` landed
    in `pve-no-subscription` (advisory PSA-2026-00027-1) — fixed.
  - PVE 9 old 6.14 (via `origin/trixie-6.14` changelog) — latest
    `6.14.11-9-pve` (2026-05-15) carries no Januscape cherry-pick —
    vulnerable.
  - PVE 8 default — `proxmox-kernel-6.8.12-33-pve` carries the
    backport, shipped 2026-07-08 — fixed.
  - PVE 8 opt-in 6.14 `bpo12` (via `origin/bookworm-6.14` changelog) —
    latest `6.14.11-9~bpo12+1` (2026-05-15) carries no Januscape
    cherry-pick — vulnerable.
  - PVE 8 old 6.11 (via `origin/bookworm-6.11` changelog) — latest
    `6.11.11-2` (2025-03-16) predates the disclosure, no cherry-pick —
    vulnerable.
  - Series lifecycle (via the Proxmox forum opt-in kernel
    announcements): an opt-in kernel previews the next default, a
    superseded series stops receiving updates barring serious issues,
    and every such series is EOL on kernel.org — the basis of the
    *old* labels and the "unlikely ever to flip" caveat.
- **NixOS** (via the local nixpkgs clone):
  - The default `linuxPackages` (`linux_6_18`) is `6.18.41` on
    nixos-unstable and `6.18.41` on nixos-26.05 — both carry the
    backport — fixed.
  - `linuxPackages_latest` (`linux_7_1`) is `7.1.5` on nixos-unstable
    and `7.1.5` on nixos-26.05.
- **Rocky / RHEL family** (via the Red Hat security data API,
  errata.almalinux.org, and Rocky BaseOS repodata):
  - EL10 / EL9 standard `kernel` — RHSA-2026:36956 (RHEL 10, fixed NVR
    `6.12.0-211.32.1.el10_2`) and RHSA-2026:36957 (RHEL 9, fixed NVR
    `5.14.0-687.24.1.el9_8`); AlmaLinux rebuilt both on 2026-07-10
    (ALSA-2026:36956 / ALSA-2026:36957); Rocky 10 and Rocky 9 BaseOS
    ship the fixed NVRs (confirmed via repodata) — fixed.
  - EL8 standard `kernel` — RHSA-2026:39083 shipped 2026-07-14 (fixed
    NVR `4.18.0-553.143.1.el8_10`); AlmaLinux 8 rebuilt as
    ALSA-2026:39083. Rocky 8 BaseOS ships `4.18.0-553.144.1.el8_10`
    via RLSA-2026:39179 (confirmed via repodata + updateinfo) — the
    build supersedes 553.143.1 and carries the backport — fixed.
  - Real-time kernels — RHSA-2026:39983 (RHEL 9.2 E4S NFV, 2026-07-15,
    `5.14.0-284.181.1.rt14.466.el9_2`) and RHSA-2026:39082 (RHEL 8
    NFV, 2026-07-14, `4.18.0-553.143.1.rt7.484.el8_10`).
  - EUS / E4S / TUS advisories (not reflected in the Rocky rows, which
    track the main RHEL releases): RHSA-2026:39371 (RHEL 10.0 EUS,
    `6.12.0-55.88.1.el10_0`), RHSA-2026:38902 (RHEL 9.6 EUS,
    `5.14.0-570.127.1.el9_6`), RHSA-2026:37729 (RHEL 9.4 EUS,
    `5.14.0-427.137.1.el9_4`), RHSA-2026:40082 (RHEL 9.2 E4S,
    `5.14.0-284.181.1.el9_2`), RHSA-2026:41229 (RHEL 8.8 TUS and
    SAP Solutions, `4.18.0-477.154.1.el8_8`, 2026-07-17), and
    RHSA-2026:49033 (RHEL 8.6 AUS and EUS Long-Life Add-On,
    `4.18.0-372.204.1.el8_6`, 2026-07-31).
- **Amazon Linux** (via repodata `updateinfo.xml.gz`):
  - AL2023 default `kernel` (6.1) — ALAS2023-2026-2001 (issued
    2026-07-24) fixes CVE-2026-53359 via cherry-pick in
    `kernel-6.1.176-221.367` — fixed.
  - AL2023 `kernel6.12` — ALAS2023-2026-1970 (issued 2026-07-20) fixes
    it via cherry-pick in `kernel6.12-6.12.94-123.190` — fixed.
  - AL2023 `kernel6.18` — ALAS2023-2026-1969 (issued 2026-07-20) fixes
    it in `kernel6.18-6.18.38-73.137`; upstream 6.18.38 carries the
    backport — fixed.
  - AL2 — reached end of support on 2026-06-30 (per the AWS AL2 FAQ;
    confirmed against endoflife.date) without an ALAS for this CVE —
    all three of its streams remain permanently vulnerable; AL2 is
    covered collectively in prose, not tracked as rows.
{{< /details >}}

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
