# Changelog

A list of notable changes in the package.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) since v1.0.0.

## [Unreleased]

## [1.5.0] - 2024-05-19
### Changed
- Try UTF-8 encoding when decoding by specified codepage fails.
- Change plain text output form to YAML-like style.
### Fixed
- Add missing import to `shell_item`.

## [1.4.0] - 2024-03-19
### Added
- Add support to process unknown (`Unknown`) blocks in `ExtraData` section
- Add support to process `Terminal` block in `ExtraData` section

## [1.3.3] - 2023-12-27
### Fixed
- Exclude tests from setup.py ([PR](https://github.com/Matmaus/LnkParse3/pull/26))

## [1.3.2] - 2023-10-07
### Fixed
- Fix metadata store to be a list

## [1.3.1] - 2023-10-07
### Fixed
- Add missing import

## [1.3.0] - 2023-10-07
### Added
- Add support to process `SerializedPropertyValue` property in `METADATA_PROPERTIES_BLOCK`
- Add support to process `IDList` property in `SHELL_ITEM_IDENTIFIER_BLOCK`
### Fixed
- Fix issues in`Local.volume_label_unicode` method
- Catch exception when parsing `StringData`
- Catch exception when detecting a proper Info class (`Local`/`Network`)
- Catch exception when parsing `ExtraData`

## [1.2.1] - 2023-09-08
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
