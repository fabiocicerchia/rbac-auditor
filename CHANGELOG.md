# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0](https://github.com/fabiocicerchia/rbac-auditor/compare/v2.0.1...v2.1.0) (2026-11-06)


### Features

* **policy:** masters-subject rule for a new binding to system:masters ([#98](https://github.com/fabiocicerchia/rbac-auditor/issues/98)) ([31c3889](https://github.com/fabiocicerchia/rbac-auditor/commit/31c38899470d4a9cd826e86e1b0e1b2df95c5c19))
* **snapshot:** --from-manifests DIR, so the gate can run on a pull request ([#99](https://github.com/fabiocicerchia/rbac-auditor/issues/99)) ([31d8a13](https://github.com/fabiocicerchia/rbac-auditor/commit/31d8a13c5a19ba44908daaf99583a3406dee577a))


### Bug Fixes

* 2 issues found by code-atlas (end-of-life runtimes) ([#106](https://github.com/fabiocicerchia/rbac-auditor/issues/106)) ([01a8f3c](https://github.com/fabiocicerchia/rbac-auditor/commit/01a8f3cd6146ec89a38b537e5a476ad005663259))
* 2 issues found by code-atlas (insights to act on) ([#103](https://github.com/fabiocicerchia/rbac-auditor/issues/103)) ([b22fb3c](https://github.com/fabiocicerchia/rbac-auditor/commit/b22fb3c665ecc74a3ccba920a796e525df5868b9))
* 2 issues found by code-atlas (quality gates) ([#104](https://github.com/fabiocicerchia/rbac-auditor/issues/104)) ([ac1f32a](https://github.com/fabiocicerchia/rbac-auditor/commit/ac1f32adbfc91b88f6c117994c1f9f9b8df6ad1b))
* 3 issues found by code-atlas (ci that cannot fail) ([#105](https://github.com/fabiocicerchia/rbac-auditor/issues/105)) ([6437fea](https://github.com/fabiocicerchia/rbac-auditor/commit/6437fead4b74191605d8b896127bb4e1c8cf24c3))
* 3 issues found by code-atlas (code design) ([#107](https://github.com/fabiocicerchia/rbac-auditor/issues/107)) ([af5ddbc](https://github.com/fabiocicerchia/rbac-auditor/commit/af5ddbc194d1025d30f0323e945291a27fa25356))
* 4 issues found by code-atlas (quality gates) ([#102](https://github.com/fabiocicerchia/rbac-auditor/issues/102)) ([cbf1b6f](https://github.com/fabiocicerchia/rbac-auditor/commit/cbf1b6f74cbe73d434e9db07c99588a0bd287742))
* 6 issues found by code-atlas (test suites) ([#108](https://github.com/fabiocicerchia/rbac-auditor/issues/108)) ([474b72f](https://github.com/fabiocicerchia/rbac-auditor/commit/474b72fb1a6848e06d352c526c9c535c8ebc35cc))

## [2.0.1](https://github.com/fabiocicerchia/rbac-auditor/compare/v2.0.0...v2.0.1) (2026-09-20)


### Bug Fixes

* **ci:** keep actions: read on the job that uploads sarif ([#82](https://github.com/fabiocicerchia/rbac-auditor/issues/82)) ([aa96d99](https://github.com/fabiocicerchia/rbac-auditor/commit/aa96d99515f25767b4fd6e68360ddaf4c2c70fa4))

## [2.0.0](https://github.com/fabiocicerchia/rbac-auditor/compare/v1.3.1...v2.0.0) (2026-09-12)


### ⚠ BREAKING CHANGES

* `report`, `dump` and `who-can` are gone, along with `--html`, `--s3`, `--fail-on-findings` and `.rbac-audit-ignore`. `dump` is replaced by `snapshot`, whose format is new and versioned; snapshots written by 1.x are not readable. Gating is now `diff` plus a policy file rather than `report --fail-on-findings`. For who-can queries and access matrices, use rakkess, rbac-tool or rbac-lookup.

### Features

* narrow to snapshotting and a policy-gated diff ([#69](https://github.com/fabiocicerchia/rbac-auditor/issues/69)) ([5be5046](https://github.com/fabiocicerchia/rbac-auditor/commit/5be5046e379b6e91ef566706f25ef7abf9ee8d4f))

## [1.3.1](https://github.com/fabiocicerchia/rbac-auditor/compare/v1.3.0...v1.3.1) (2026-09-10)


### Bug Fixes

* **release:** actually trigger the image publish ([#66](https://github.com/fabiocicerchia/rbac-auditor/issues/66)) ([cb2d093](https://github.com/fabiocicerchia/rbac-auditor/commit/cb2d093e8604317ff4ec387e516d6150b62824fb))

## [1.3.0](https://github.com/fabiocicerchia/rbac-auditor/compare/v1.2.2...v1.3.0) (2026-09-09)


### Features

* **packaging:** make it installable, with a man page ([#61](https://github.com/fabiocicerchia/rbac-auditor/issues/61)) ([126dfdc](https://github.com/fabiocicerchia/rbac-auditor/commit/126dfdccafebf682fa57682484c703aa7017188a))

## [1.2.2](https://github.com/fabiocicerchia/rbac-auditor/compare/v1.2.1...v1.2.2) (2026-09-04)

### Bug Fixes

- **ci:** pin the editorconfig-checker binary version ([#49](https://github.com/fabiocicerchia/rbac-auditor/issues/49)) ([072abe4](https://github.com/fabiocicerchia/rbac-auditor/commit/072abe4a8c2e52d0ba16e941d2fdc9d9c55ad596))

## [1.2.1](https://github.com/fabiocicerchia/rbac-auditor/compare/v1.2.0...v1.2.1) (2026-08-29)

### Bug Fixes

- unblock quality and clear the Scorecard pinned-dependencies finding ([#40](https://github.com/fabiocicerchia/rbac-auditor/issues/40)) ([3116467](https://github.com/fabiocicerchia/rbac-auditor/commit/31164679e53c98b45f9742ddb496e3badc9f3d9e))

## [1.2.0](https://github.com/fabiocicerchia/rbac-auditor/compare/v1.1.0...v1.2.0) (2026-08-25)

### Features

- **docs:** build the docs site in Actions and drop Read the Docs ([#38](https://github.com/fabiocicerchia/rbac-auditor/issues/38)) ([b4ace9f](https://github.com/fabiocicerchia/rbac-auditor/commit/b4ace9fff49aabdcb60340ce9a7783615d333c40))

## [1.1.0](https://github.com/fabiocicerchia/rbac-auditor/compare/v1.0.1...v1.1.0) (2026-08-24)

### Features

- **report:** self-contained HTML report with optional S3 upload ([#28](https://github.com/fabiocicerchia/rbac-auditor/issues/28)) ([38fcb58](https://github.com/fabiocicerchia/rbac-auditor/commit/38fcb58cbbf2bb481e81d1d5e7b9a68eb886290a))
- **report:** suppress accepted findings with .rbac-audit-ignore ([#27](https://github.com/fabiocicerchia/rbac-auditor/issues/27)) ([9356cb6](https://github.com/fabiocicerchia/rbac-auditor/commit/9356cb6f616fe476d6e5ed7ee09c056146d2ac5b))

## [1.0.1](https://github.com/fabiocicerchia/rbac-auditor/compare/v1.0.0...v1.0.1) (2026-08-13)

### Bug Fixes

- security and code-quality findings ([#23](https://github.com/fabiocicerchia/rbac-auditor/issues/23)) ([4f22c46](https://github.com/fabiocicerchia/rbac-auditor/commit/4f22c46311a586562be05384efaebaa838e017c7))

## 1.0.0 (2026-08-06)

### Features

- **chart:** add Helm chart ([e24923f](https://github.com/fabiocicerchia/rbac-auditor/commit/e24923fd2b44d37b71d0d87c141897f1650ea70e))

### Bug Fixes

- **ci:** stop security workflows failing on private repos ([#10](https://github.com/fabiocicerchia/rbac-auditor/issues/10)) ([930a238](https://github.com/fabiocicerchia/rbac-auditor/commit/930a2382527790749158b1abd9dd6a32a4bd3e4e))
- **pre-commit:** stop check-yaml failing on Helm templates and multi-doc manifests ([34c2353](https://github.com/fabiocicerchia/rbac-auditor/commit/34c23537628a29a707d4d974d5401be85ec0b5c3))
- surface kubectl stderr instead of a traceback ([bfc774d](https://github.com/fabiocicerchia/rbac-auditor/commit/bfc774d09cad95ffdefcec37e9326f6bde12a9f4))
- surface kubectl stderr instead of a traceback ([e2a91e9](https://github.com/fabiocicerchia/rbac-auditor/commit/e2a91e9b1a7643a66798949339a1d58de56b1d6d))
- **test:** assert the traceback is absent without skipping errexit ([2bec056](https://github.com/fabiocicerchia/rbac-auditor/commit/2bec056e25e7530f20e54aa432b243a3da562a19))
- verify the kubectl download against its published checksum ([89bb093](https://github.com/fabiocicerchia/rbac-auditor/commit/89bb0938b1c58e59d88167b01b9d2643ff3faaec))

## [Unreleased]

### Added

- `report`, `dump`, `diff` and `who-can` over Kubernetes RBAC, plus a
  read-only ClusterRole and CronJob manifest for a weekly in-cluster report.

Not yet released.
