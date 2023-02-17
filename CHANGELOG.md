# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2022-12-15

### Fixed

-   Fixed Json LD serialization bug which prevented multi-BPN policies to be defined and used. Checkout the [docs](https://github.com/catenax-ng/product-edc/blob/0.2.0/edc-extensions/business-partner-validation/README.md) for more info.

## [0.1.3] - 2022-11-30

### Added

-   New Postman collection for developers `/docs/development/postman`
-   New EDC Image with HashiCorp Vault and InMemory Storage
-   (Experimental) Simplified deployment of the EDC in `/charts/tractusx-connector`

### Changed

-   Set EDC version to `0.0.1-20221006-SNAPSHOT`
-   Business Partner Number Extension no longer supports the 'IN' constraint operator
-   HashiCorp Vault Extension now allows sub directories for secrets
-   Update package structure/namespace from `net.catenax` to `org.eclipse.tractusx`

### Fixed

-   S3 Data Transfer

## [0.1.2] - 2022-09-30

### Added

-   Introduced DEPENDENCIES file

### Changed

-   Moved helm charts from `deployment/helm` to `charts`

## [0.1.1] - 2022-09-04

**Important Note**: Please consolidate the migration documentation before updating your connector. [documentation](/docs/migration/Version_0.1.0_0.1.1.md).

### Added

-   Control-Plane Extension ([cx-oauth2](/edc-extensions/cx-oauth2/README.md))

### Changed

-   Introduced git submodule to import EDC dependencies (instead of snapshot- or milestone artifact)
-   Helm Charts: TLS secret name is now configurable

### Fixed

-   Connectors with Azure Vault extension are now starting again [link](https://github.com/eclipse-edc/Connector/issues/1892)

## [0.1.0] - 2022-08-19

**Important Note**: Version 0.1.0 introduces multiple breaking changes. Before updating **always** consolidate the
corresponding [documentation](/docs/migration/Version_0.0.x_0.1.x.md).

### Added

-   Control-Plane extension ([data-plane-selector-client](https://github.com/eclipse-edc/Connector/tree/v0.0.1-milestone-5/extensions/data-plane-selector/selector-client))
    -   run the EDC with multiple data planes at once
-   Control-Plane extension ([dataplane-selector-configuration](edc-extensions/dataplane-selector-configuration))
    -   add data plane instances to the control plane by configuration
-   Data-Plane extension ([s3-data-plane](https://github.com/eclipse-edc/Connector/tree/main/extensions/aws/data-plane-s3))
    -   transfer from and to AWS S3 buckets
-   Control-Plane extension ([data-encryption](edc-extensions/data-encryption))
    -   Data-Plane authentication attribute transmitted during data-plane-transfer can be encrypted symmetrically (AES)

### Changed

-   Update setting name (`edc.dataplane.token.validation.endpoint` -> `edc.dataplane.token.validation.endpoint`)
-   EDC has been updated to version [0.0.1-20220818-SNAPSHOT](https://oss.sonatype.org/#nexus-search;gav~org.eclipse.dataspaceconnector~~0.0.1-20220818-SNAPSHOT~~) - implications to the behavior of the connector have been covered in the [corresponding migration guide](docs/migration/Version_0.0.x_0.1.x.md)

### Fixed

-   Contract-Offer-Receiving-Connectors must also pass the ContractPolicy of the ContractDefinition before receiving offers([issue](https://github.com/eclipse-edc/Connector/issues/1331))
-   Deletion of Asset becomes impossible when Contract Negotiation exists([issue](https://github.com/eclipse-edc/Connector/issues/1403))
-   Deletion of Policy becomes impossible when Contract Definition exists([issue](https://github.com/eclipse-edc/Connector/issues/1410))

## [0.0.6] - 2022-07-29

### Fixed

-   Fixes [release 0.0.5](https://github.com/catenax-ng/product-edc/releases/tag/0.0.5), which introduced classpath issues due to usage of [net.jodah:failsafe:2.4.3](https://search.maven.org/artifact/net.jodah/failsafe/2.4.3/jar) library 

## [0.0.5] - 2022-07-28

### Added

-   EDC Health Checks for HashiCorp Vault

### Changed

-   BusinessPartnerNumber constraint supports List structure
-   Helm: Confidential EDC settings can be set using k8s secrets
-   HashiCorp Vault API path configurable

## [0.0.4] - 2022-06-27

### Added

-   HashiCorp Vault Extension
-   Control Plane with HashiCorp Vault and PostgreSQL support

### Changed

-   Release Worklow now publishes Product EDC Extensions as Maven Artifacts

### Fixed

-   [#1515](https://github.com/eclipse-edc/Connector/issues/1515) SQL: Connector sends out 50
    contract offers max.

### Removed

-   CosmosDB Control Plane
-   Control API Extension for all Control Planes

## [0.0.3] - 2022-05-23

## [0.0.2] - 2022-05-20

## [0.0.1] - 2022-05-13

[Unreleased]: https://github.com/catenax-ng/product-edc/compare/0.2.0...HEAD

[0.2.0]: https://github.com/catenax-ng/product-edc/compare/0.1.3...0.2.0

[0.1.3]: https://github.com/catenax-ng/product-edc/compare/0.1.2...0.1.3

[0.1.2]: https://github.com/catenax-ng/product-edc/compare/0.1.1...0.1.2

[0.1.1]: https://github.com/catenax-ng/product-edc/compare/0.1.0...0.1.1

[0.1.0]: https://github.com/catenax-ng/product-edc/compare/0.0.6...0.1.0

[0.0.6]: https://github.com/catenax-ng/product-edc/compare/0.0.5...0.0.6

[0.0.5]: https://github.com/catenax-ng/product-edc/compare/0.0.4...0.0.5

[0.0.4]: https://github.com/catenax-ng/product-edc/compare/0.0.3...0.0.4

[0.0.3]: https://github.com/catenax-ng/product-edc/compare/0.0.2...0.0.3

[0.0.2]: https://github.com/catenax-ng/product-edc/compare/0.0.1...0.0.2

[0.0.1]: https://github.com/catenax-ng/product-edc/compare/a02601306fed39a88a3b3b18fae98b80791157b9...0.0.1
