# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0 (2026-08-06)


### Features

* **chart:** add Helm chart ([e24923f](https://github.com/fabiocicerchia/rbac-auditor/commit/e24923fd2b44d37b71d0d87c141897f1650ea70e))


### Bug Fixes

* **ci:** stop security workflows failing on private repos ([#10](https://github.com/fabiocicerchia/rbac-auditor/issues/10)) ([930a238](https://github.com/fabiocicerchia/rbac-auditor/commit/930a2382527790749158b1abd9dd6a32a4bd3e4e))
* **pre-commit:** stop check-yaml failing on Helm templates and multi-doc manifests ([34c2353](https://github.com/fabiocicerchia/rbac-auditor/commit/34c23537628a29a707d4d974d5401be85ec0b5c3))
* surface kubectl stderr instead of a traceback ([bfc774d](https://github.com/fabiocicerchia/rbac-auditor/commit/bfc774d09cad95ffdefcec37e9326f6bde12a9f4))
* surface kubectl stderr instead of a traceback ([e2a91e9](https://github.com/fabiocicerchia/rbac-auditor/commit/e2a91e9b1a7643a66798949339a1d58de56b1d6d))
* **test:** assert the traceback is absent without skipping errexit ([2bec056](https://github.com/fabiocicerchia/rbac-auditor/commit/2bec056e25e7530f20e54aa432b243a3da562a19))
* verify the kubectl download against its published checksum ([89bb093](https://github.com/fabiocicerchia/rbac-auditor/commit/89bb0938b1c58e59d88167b01b9d2643ff3faaec))

## [Unreleased]

### Added

- `report`, `dump`, `diff` and `who-can` over Kubernetes RBAC, plus a
  read-only ClusterRole and CronJob manifest for a weekly in-cluster report.

Not yet released.
