# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.10.4] - 2022-11-24
### Updated
- `@subql/node-core` dependency updated.

## [1.10.3] - 2022-11-10
### Added
- Retry request when encountering timeout/rate limit behaviours. (#25)

## [1.10.2] - 2022-11-08
### Changed
- Sync with the latest changes with @subql/node-core, remove sequelize alter table

## [1.10.1] - 2022-10-11
### Changed
- Sync with latest changes on Substrate SDK:
  - Remove deprecated subqueries table

## [1.10.0] - 2022-10-06
### Updated
- `@subql/common` dependency updated.

### Fixed
- Finalized head not updating correctly for new blocks. (#18)
### Changed
- Sync with latest changes on Substrate SDK:
  - New `reindex` and `force-clean` subcommands.
  - Enable historical feature by default.

## [1.9.4] - 2022-09-29
### Fixed
- Fix unable initialize due to missing sequelize in `node-core` package (#15)

## [1.9.3] - 2022-09-27
## Fixed
- Fix abi parsing not being applied to data. (#13)
- Fix address not being applied to filters. (#13)

## [1.9.2] - 2022-09-15
### Fixed
- Removed Substrate and Algorand specific types and added custom DataSource support. (#7)

## [1.9.1] - 2022-09-08
### Fixed
- Fix issue with chain id being compared to genesis hash. (#8)

## [1.9.0] - 2022-09-07

### Changed
- Sync with Substrate SDK to include all latest features. See the [Substrate Changelog](https://github.com/subquery/subql-cosmos/blob/main/packages/node/CHANGELOG.md#190---2022-09-02) for more details.
  - Worker threads.
  - POI improvements.
  - Use `@subql/node-core` package.
  - Store improvements like bulk operations and paging results.

### Added
- Support for api keys via url parameters and convert them to headers.

## [0.3.0] - 2022-07-28
### Fixed
- Error logging erro with arguments with bigint values.

### Added
- Support endpoints with paths like `/public`. (#1213)

## [0.2.0] - 2022-06-27
### Added
- Add Eth provider to query contracts and other changes (#1143)

## [0.1.1] - 2022-06-27
### Added
- init commit
