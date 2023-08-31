# Changelog

A list of notable changes in the package.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) since v1.0.0.

## [Unreleased]
### Fixed
- Catch possible exception when processing extra_factory data, where a size is reported with no accompanying data (@ddash-ct)

## [1.2.0] - 2021-07-19
### Fixed
- Catch more exceptions, and use warnings instead
- Replace unknown characters in UTF-16
- Fix parsing and output position of LNK info (`common_path_suffix`, `local_base_path`, ...)
- Fix printing of `net_name`, `device_name`, and `local_base_path`

### Changed
- Treat `0` time as a valid value (it means a file was created in an application and never ever opened)
- Always return at least target name when there is any problem
- Disable `MyComputer` target (it is not implemented yet)

## [1.1.1] - 2021-04-17
### Changed
- Even unimplemented target will return at least its name ([PR](https://github.com/Matmaus/LnkParse3/pull/17))
### Fixed
- Fix incorrect conversion of DOS time ([issue](https://github.com/Matmaus/LnkParse3/issues/15), [PR](https://github.com/Matmaus/LnkParse3/pull/16))

## [1.1.0] - 2021-03-16
### Added
- Support for additional parsing of Darwin block ([issue](https://github.com/Matmaus/LnkParse3/issues/13), [PR](https://github.com/Matmaus/LnkParse3/pull/14))

## [1.0.0] - 2021-01-21

- Initial release (the previous ones are considered pre-releases and do not follow semantic versioning)
