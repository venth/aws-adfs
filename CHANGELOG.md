# Changelog

## [2.4.0](https://github.com/venth/aws-adfs/tree/2.4.0) (2022-06-22)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.3.3...2.4.0)

**Merged pull requests:**

- Improve factor and device selection with Duo Universal Prompt [\#264](https://github.com/venth/aws-adfs/pull/264) ([pdecat](https://github.com/pdecat))
- Bump boto3 from 1.24.11 to 1.24.13 [\#263](https://github.com/venth/aws-adfs/pull/263) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump botocore from 1.27.13 to 1.27.14 [\#262](https://github.com/venth/aws-adfs/pull/262) ([dependabot[bot]](https://github.com/apps/dependabot))

## [2.3.3](https://github.com/venth/aws-adfs/tree/2.3.3) (2022-06-22)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.3.2...2.3.3)

**Merged pull requests:**

- Bump botocore from 1.27.11 to 1.27.13 [\#261](https://github.com/venth/aws-adfs/pull/261) ([dependabot[bot]](https://github.com/apps/dependabot))
- Tolerate missing 'transports' key from WebAuthn challenge, and fix regression with CTAP1 device since fido2 1.0.0 [\#260](https://github.com/venth/aws-adfs/pull/260) ([pdecat](https://github.com/pdecat))
- Bump boto3 from 1.24.5 to 1.24.11 [\#259](https://github.com/venth/aws-adfs/pull/259) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump botocore from 1.27.7 to 1.27.11 [\#257](https://github.com/venth/aws-adfs/pull/257) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump botocore from 1.27.5 to 1.27.7 [\#252](https://github.com/venth/aws-adfs/pull/252) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump requests from 2.27.1 to 2.28.0 [\#251](https://github.com/venth/aws-adfs/pull/251) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump actions/setup-python from 3 to 4 [\#246](https://github.com/venth/aws-adfs/pull/246) ([dependabot[bot]](https://github.com/apps/dependabot))

## [2.3.2](https://github.com/venth/aws-adfs/tree/2.3.2) (2022-06-10)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.3.1...2.3.2)

**Fixed bugs:**

- `login --role-arn "?"` not working on an existing profile [\#227](https://github.com/venth/aws-adfs/issues/227)

**Merged pull requests:**

- Add pre-commit hooks [\#249](https://github.com/venth/aws-adfs/pull/249) ([pdecat](https://github.com/pdecat))
- Disable cache when role\_arn is '?' [\#247](https://github.com/venth/aws-adfs/pull/247) ([pdecat](https://github.com/pdecat))

## [2.3.1](https://github.com/venth/aws-adfs/tree/2.3.1) (2022-06-09)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.3.0...2.3.1)

**Merged pull requests:**

- Hotfix python 3.10 version in .github/workflows/build.yml :facepalm: [\#248](https://github.com/venth/aws-adfs/pull/248) ([pdecat](https://github.com/pdecat))

## [2.3.0](https://github.com/venth/aws-adfs/tree/2.3.0) (2022-06-09)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.2.2...2.3.0)

**Fixed bugs:**

- fido2 1.0.0 breaks aws-adfs [\#243](https://github.com/venth/aws-adfs/issues/243)

**Merged pull requests:**

- Drop support for python 3.6 and update dependencies \(and define better constraints as pip does not honor poetry.lock\) [\#245](https://github.com/venth/aws-adfs/pull/245) ([pdecat](https://github.com/pdecat))

## [2.2.2](https://github.com/venth/aws-adfs/tree/2.2.2) (2022-06-08)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.2.1...2.2.2)

**Merged pull requests:**

- Pin fido2 to below 1.0.0 [\#244](https://github.com/venth/aws-adfs/pull/244) ([erpel](https://github.com/erpel))

## [2.2.1](https://github.com/venth/aws-adfs/tree/2.2.1) (2022-06-03)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.2.0...2.2.1)

**Closed issues:**

- cache file truncation [\#234](https://github.com/venth/aws-adfs/issues/234)

**Merged pull requests:**

- Avoid exception when multiple FIDO authenticators are present [\#242](https://github.com/venth/aws-adfs/pull/242) ([pdecat](https://github.com/pdecat))
- Bump lxml from 4.8.0 to 4.9.0 [\#237](https://github.com/venth/aws-adfs/pull/237) ([dependabot[bot]](https://github.com/apps/dependabot))

## [2.2.0](https://github.com/venth/aws-adfs/tree/2.2.0) (2022-06-03)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.1.0...2.2.0)

**Merged pull requests:**

- Allow overriding the Duo factor and device to use [\#240](https://github.com/venth/aws-adfs/pull/240) ([pdecat](https://github.com/pdecat))

## [2.1.0](https://github.com/venth/aws-adfs/tree/2.1.0) (2022-06-02)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.1.0-alpha.2...2.1.0)

**Closed issues:**

- Duo Universal Prompt breaks aws-adfs compatibility [\#236](https://github.com/venth/aws-adfs/issues/236)

**Merged pull requests:**

- Support Duo Universal Prompt [\#238](https://github.com/venth/aws-adfs/pull/238) ([pdecat](https://github.com/pdecat))

## [2.1.0-alpha.2](https://github.com/venth/aws-adfs/tree/2.1.0-alpha.2) (2022-06-02)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.1.0-alpha.1...2.1.0-alpha.2)

## [2.1.0-alpha.1](https://github.com/venth/aws-adfs/tree/2.1.0-alpha.1) (2022-06-02)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.5...2.1.0-alpha.1)

## [2.0.5](https://github.com/venth/aws-adfs/tree/2.0.5) (2022-06-01)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.4...2.0.5)

**Merged pull requests:**

- Disable cache if `role_arn` is not provided [\#232](https://github.com/venth/aws-adfs/pull/232) ([pdecat](https://github.com/pdecat))

## [2.0.4](https://github.com/venth/aws-adfs/tree/2.0.4) (2022-06-01)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.3...2.0.4)

**Merged pull requests:**

- Adding truncate flag when opening the credential cache file. [\#235](https://github.com/venth/aws-adfs/pull/235) ([mattmauriello](https://github.com/mattmauriello))

## [2.0.3](https://github.com/venth/aws-adfs/tree/2.0.3) (2022-05-07)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.2...2.0.3)

**Merged pull requests:**

- feat\(doc\): use github-changelog-generator for generating CHANGELOG.md [\#233](https://github.com/venth/aws-adfs/pull/233) ([pdecat](https://github.com/pdecat))
- Hide RSA token [\#231](https://github.com/venth/aws-adfs/pull/231) ([gchambert](https://github.com/gchambert))

## [2.0.2](https://github.com/venth/aws-adfs/tree/2.0.2) (2022-04-27)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.1...2.0.2)

**Merged pull requests:**

- Switch to poetry-core [\#230](https://github.com/venth/aws-adfs/pull/230) ([fabaff](https://github.com/fabaff))
- Bump actions/checkout from 2 to 3 [\#226](https://github.com/venth/aws-adfs/pull/226) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump actions/setup-python from 2 to 3 [\#225](https://github.com/venth/aws-adfs/pull/225) ([dependabot[bot]](https://github.com/apps/dependabot))

## [2.0.1](https://github.com/venth/aws-adfs/tree/2.0.1) (2022-02-26)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.0...2.0.1)

**Fixed bugs:**

- going back and forth between multiple hosts [\#222](https://github.com/venth/aws-adfs/issues/222)

**Merged pull requests:**

- Added hashlib dependency and adfs hostname hash to cookie jar filename [\#223](https://github.com/venth/aws-adfs/pull/223) ([mattmauriello](https://github.com/mattmauriello))
- Bump click from 8.0.3 to 8.0.4 [\#221](https://github.com/venth/aws-adfs/pull/221) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump lxml from 4.7.1 to 4.8.0 [\#220](https://github.com/venth/aws-adfs/pull/220) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump boto3 from 1.20.53 to 1.20.54 [\#219](https://github.com/venth/aws-adfs/pull/219) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump boto3 from 1.20.52 to 1.20.53 [\#218](https://github.com/venth/aws-adfs/pull/218) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump pytest from 7.0.0 to 7.0.1 [\#217](https://github.com/venth/aws-adfs/pull/217) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump botocore from 1.23.53 to 1.23.54 [\#216](https://github.com/venth/aws-adfs/pull/216) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump botocore from 1.23.52 to 1.23.53 [\#215](https://github.com/venth/aws-adfs/pull/215) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump boto3 from 1.20.51 to 1.20.52 [\#214](https://github.com/venth/aws-adfs/pull/214) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump botocore from 1.23.51 to 1.23.52 [\#213](https://github.com/venth/aws-adfs/pull/213) ([dependabot[bot]](https://github.com/apps/dependabot))

## [2.0.0](https://github.com/venth/aws-adfs/tree/2.0.0) (2022-02-09)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.0-alpha.11...2.0.0)

**Closed issues:**

- Support Duo webauthn [\#208](https://github.com/venth/aws-adfs/issues/208)

**Merged pull requests:**

- Bump botocore from 1.23.50 to 1.23.51 [\#212](https://github.com/venth/aws-adfs/pull/212) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump coverage from 3.7.1 to 6.2 [\#211](https://github.com/venth/aws-adfs/pull/211) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump pytest from 6.2.5 to 7.0.0 [\#210](https://github.com/venth/aws-adfs/pull/210) ([dependabot[bot]](https://github.com/apps/dependabot))
- Switch from U2F to WebAuthn for DUO authentication [\#209](https://github.com/venth/aws-adfs/pull/209) ([pdecat](https://github.com/pdecat))

## [2.0.0-alpha.11](https://github.com/venth/aws-adfs/tree/2.0.0-alpha.11) (2022-02-09)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.0-alpha.10...2.0.0-alpha.11)

## [2.0.0-alpha.10](https://github.com/venth/aws-adfs/tree/2.0.0-alpha.10) (2022-02-09)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.0-alpha.9...2.0.0-alpha.10)

## [2.0.0-alpha.9](https://github.com/venth/aws-adfs/tree/2.0.0-alpha.9) (2022-02-09)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.0-alpha.8...2.0.0-alpha.9)

## [2.0.0-alpha.8](https://github.com/venth/aws-adfs/tree/2.0.0-alpha.8) (2022-02-09)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.0-alpha.7...2.0.0-alpha.8)

## [2.0.0-alpha.7](https://github.com/venth/aws-adfs/tree/2.0.0-alpha.7) (2022-02-09)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.0-alpha.2...2.0.0-alpha.7)

**Implemented enhancements:**

- Provide a command or option to get the console link [\#143](https://github.com/venth/aws-adfs/issues/143)

**Merged pull requests:**

- Print AWS web console sign-in url [\#197](https://github.com/venth/aws-adfs/pull/197) ([pdecat](https://github.com/pdecat))
- Add `--username-password-command` to read username and password from the output of a shell command [\#196](https://github.com/venth/aws-adfs/pull/196) ([pdecat](https://github.com/pdecat))

## [2.0.0-alpha.2](https://github.com/venth/aws-adfs/tree/2.0.0-alpha.2) (2022-01-29)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.0-alpha.1...2.0.0-alpha.2)

**Merged pull requests:**

- Update dependencies and drop python 3.5 support [\#206](https://github.com/venth/aws-adfs/pull/206) ([pdecat](https://github.com/pdecat))

## [2.0.0-alpha.1](https://github.com/venth/aws-adfs/tree/2.0.0-alpha.1) (2022-01-26)

[Full Changelog](https://github.com/venth/aws-adfs/compare/2.0.0-alpha.0...2.0.0-alpha.1)

## [2.0.0-alpha.0](https://github.com/venth/aws-adfs/tree/2.0.0-alpha.0) (2022-01-26)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.25.0-alpha.2...2.0.0-alpha.0)

**Implemented enhancements:**

- AWS session caching is not implemented, ADFS is called every time [\#182](https://github.com/venth/aws-adfs/issues/182)

**Closed issues:**

- printenv should output only shell commands, the summary isn't [\#180](https://github.com/venth/aws-adfs/issues/180)

**Merged pull requests:**

- Update poetry from 1.1.10 to 1.1.11 to fix python 3.10 compatibility [\#202](https://github.com/venth/aws-adfs/pull/202) ([pdecat](https://github.com/pdecat))
- Trigger Github Actions build job on all push tags events [\#201](https://github.com/venth/aws-adfs/pull/201) ([pdecat](https://github.com/pdecat))
- Trigger Github Actions build job on push events to tags starting with 'v' [\#200](https://github.com/venth/aws-adfs/pull/200) ([pdecat](https://github.com/pdecat))
- Add session credentials cache [\#195](https://github.com/venth/aws-adfs/pull/195) ([pdecat](https://github.com/pdecat))
- printenv excludes summary to be shell readable [\#181](https://github.com/venth/aws-adfs/pull/181) ([Tantalon](https://github.com/Tantalon))

## [1.25.0-alpha.2](https://github.com/venth/aws-adfs/tree/1.25.0-alpha.2) (2021-09-30)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.24.5...1.25.0-alpha.2)

**Implemented enhancements:**

- Support AWS\_DEFAULT\_PROFILE [\#123](https://github.com/venth/aws-adfs/issues/123)
- Duo authenticator status code calling [\#80](https://github.com/venth/aws-adfs/issues/80)
- Feature request / security : read username and password from file [\#78](https://github.com/venth/aws-adfs/issues/78)
- parameter --profile= should have precedence over environment variable [\#63](https://github.com/venth/aws-adfs/issues/63)

**Fixed bugs:**

- del password and python string objects [\#187](https://github.com/venth/aws-adfs/issues/187)
- Login issues solved by changing the code and parameters [\#142](https://github.com/venth/aws-adfs/issues/142)
- If env AWS\_PROFILE or AWS\_DEFAULT\_PROFILE are set, a nonsensical provider\_id is used. [\#60](https://github.com/venth/aws-adfs/issues/60)

**Closed issues:**

- SAML parsing breaks on ADFS because it expects a specific XML prefix [\#184](https://github.com/venth/aws-adfs/issues/184)
- Getting the below Error [\#161](https://github.com/venth/aws-adfs/issues/161)
- This account does not have access to any roles [\#98](https://github.com/venth/aws-adfs/issues/98)

**Merged pull requests:**

- Depend on requests-negotiate-sspi on Windows. On other platforms, depend on requests-kerberos and pykerberos. [\#199](https://github.com/venth/aws-adfs/pull/199) ([pdecat](https://github.com/pdecat))
- Use Poetry for project and dependencies management [\#194](https://github.com/venth/aws-adfs/pull/194) ([pdecat](https://github.com/pdecat))
- Fix Github Actions build job [\#193](https://github.com/venth/aws-adfs/pull/193) ([pdecat](https://github.com/pdecat))
- Compiling lxml from source is no longer needed with python 3.9 [\#192](https://github.com/venth/aws-adfs/pull/192) ([pdecat](https://github.com/pdecat))
- Github Actions no longer supports python 3.4 [\#191](https://github.com/venth/aws-adfs/pull/191) ([pdecat](https://github.com/pdecat))
- Properly erase password from memory [\#190](https://github.com/venth/aws-adfs/pull/190) ([pdecat](https://github.com/pdecat))
- Automate PyPI publishing with poetry PEP517 built dists [\#177](https://github.com/venth/aws-adfs/pull/177) ([pdecat](https://github.com/pdecat))

## [1.24.5](https://github.com/venth/aws-adfs/tree/1.24.5) (2020-10-12)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.24.4...1.24.5)

**Closed issues:**

- There was an issue when following the Duo result URL after authentication [\#168](https://github.com/venth/aws-adfs/issues/168)

**Merged pull requests:**

- GitHub actions [\#172](https://github.com/venth/aws-adfs/pull/172) ([pdecat](https://github.com/pdecat))
- Support Duo bypassing MFA requests [\#169](https://github.com/venth/aws-adfs/pull/169) ([pdecat](https://github.com/pdecat))
- Add python 3.9 support [\#166](https://github.com/venth/aws-adfs/pull/166) ([pdecat](https://github.com/pdecat))

## [1.24.4](https://github.com/venth/aws-adfs/tree/1.24.4) (2020-07-05)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.24.3...1.24.4)

**Implemented enhancements:**

- NO\_PROXY Environment Variable [\#77](https://github.com/venth/aws-adfs/issues/77)

**Closed issues:**

- integration to aws credential\_process [\#112](https://github.com/venth/aws-adfs/issues/112)

**Merged pull requests:**

- Add python 3.9-dev support [\#165](https://github.com/venth/aws-adfs/pull/165) ([pdecat](https://github.com/pdecat))
- Feature credential process [\#164](https://github.com/venth/aws-adfs/pull/164) ([mikereinhold](https://github.com/mikereinhold))

## [1.24.3](https://github.com/venth/aws-adfs/tree/1.24.3) (2020-03-17)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.24.2...1.24.3)

**Closed issues:**

- Duo authentication not working with later versions of aws-adfs [\#157](https://github.com/venth/aws-adfs/issues/157)

**Merged pull requests:**

- Always return the same number of values from \_initiate\_authentication\(\) [\#160](https://github.com/venth/aws-adfs/pull/160) ([pdecat](https://github.com/pdecat))

## [1.24.2](https://github.com/venth/aws-adfs/tree/1.24.2) (2020-03-07)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.24.1...1.24.2)

**Closed issues:**

- GovCloud Initial Login [\#102](https://github.com/venth/aws-adfs/issues/102)

**Merged pull requests:**

- Ask for authentication method if there is no default method set in Duo Security settings [\#158](https://github.com/venth/aws-adfs/pull/158) ([johan1252](https://github.com/johan1252))

## [1.24.1](https://github.com/venth/aws-adfs/tree/1.24.1) (2020-02-13)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.24.0...1.24.1)

**Merged pull requests:**

- Add support for non-public AWS regions \(e.g. GovCloud\) [\#156](https://github.com/venth/aws-adfs/pull/156) ([gregorydulin](https://github.com/gregorydulin))

## [1.24.0](https://github.com/venth/aws-adfs/tree/1.24.0) (2020-01-25)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.23.0...1.24.0)

**Merged pull requests:**

- Change `AuthMethod` parameter to `FormsAuthentication` [\#151](https://github.com/venth/aws-adfs/pull/151) ([rheemskerk](https://github.com/rheemskerk))

## [1.23.0](https://github.com/venth/aws-adfs/tree/1.23.0) (2020-01-23)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.22.0...1.23.0)

**Merged pull requests:**

- Fix authentication with cookies on non-windows system. [\#154](https://github.com/venth/aws-adfs/pull/154) ([rheemskerk](https://github.com/rheemskerk))
- Fix username and password disclosure [\#153](https://github.com/venth/aws-adfs/pull/153) ([rheemskerk](https://github.com/rheemskerk))

## [1.22.0](https://github.com/venth/aws-adfs/tree/1.22.0) (2019-12-29)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.21.2...1.22.0)

**Merged pull requests:**

- Default SSPI to True on Windows only, False otherwise [\#150](https://github.com/venth/aws-adfs/pull/150) ([pdecat](https://github.com/pdecat))

## [1.21.2](https://github.com/venth/aws-adfs/tree/1.21.2) (2019-12-28)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.21.1...1.21.2)

**Closed issues:**

- Potential dependency conflicts between aws-adfs and botocore [\#148](https://github.com/venth/aws-adfs/issues/148)

**Merged pull requests:**

- Drop boto3 dependency [\#149](https://github.com/venth/aws-adfs/pull/149) ([pdecat](https://github.com/pdecat))

## [1.21.1](https://github.com/venth/aws-adfs/tree/1.21.1) (2019-12-18)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.21.0...1.21.1)

**Closed issues:**

- Installation for aws-adfs fails [\#146](https://github.com/venth/aws-adfs/issues/146)

**Merged pull requests:**

- Document new libkrb5-dev system dependency for pykerberos [\#147](https://github.com/venth/aws-adfs/pull/147) ([pdecat](https://github.com/pdecat))

## [1.21.0](https://github.com/venth/aws-adfs/tree/1.21.0) (2019-12-17)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.20.0...1.21.0)

**Closed issues:**

- Should requests\_negotiate\_sspi work on a Linux box? [\#100](https://github.com/venth/aws-adfs/issues/100)

**Merged pull requests:**

- Duo: support U2F with no preferred factor or device configured [\#145](https://github.com/venth/aws-adfs/pull/145) ([pdecat](https://github.com/pdecat))
- Kerberos support [\#144](https://github.com/venth/aws-adfs/pull/144) ([bodgit](https://github.com/bodgit))

## [1.20.0](https://github.com/venth/aws-adfs/tree/1.20.0) (2019-12-03)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.19.1...1.20.0)

**Merged pull requests:**

- U2F: fido2 v0.8.1 compatibility \(U2FClient.sign timeout renamed to event\) [\#141](https://github.com/venth/aws-adfs/pull/141) ([pdecat](https://github.com/pdecat))
- Pin fido2 dependency to \< 0.8.0 as it is a breaking release [\#140](https://github.com/venth/aws-adfs/pull/140) ([pdecat](https://github.com/pdecat))

## [1.19.1](https://github.com/venth/aws-adfs/tree/1.19.1) (2019-11-16)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.19.0...1.19.1)

**Merged pull requests:**

- Do not print stack trace if no U2F device is available [\#138](https://github.com/venth/aws-adfs/pull/138) ([pdecat](https://github.com/pdecat))

## [1.19.0](https://github.com/venth/aws-adfs/tree/1.19.0) (2019-10-15)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.18.1...1.19.0)

**Merged pull requests:**

- Fix AttributeError: 'generator' object has no attribute 'append' on python3 [\#136](https://github.com/venth/aws-adfs/pull/136) ([pdecat](https://github.com/pdecat))
- Add options to trigger or not the default authentication method when U2F is available [\#135](https://github.com/venth/aws-adfs/pull/135) ([pdecat](https://github.com/pdecat))

## [1.18.1](https://github.com/venth/aws-adfs/tree/1.18.1) (2019-09-26)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.18.0...1.18.1)

**Merged pull requests:**

- Run tests with python 3.6, 3.7 and 3.8-dev [\#131](https://github.com/venth/aws-adfs/pull/131) ([pdecat](https://github.com/pdecat))

## [1.18.0](https://github.com/venth/aws-adfs/tree/1.18.0) (2019-09-25)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.17.0...1.18.0)

**Closed issues:**

- ERROR: Cannot extract roles from response [\#128](https://github.com/venth/aws-adfs/issues/128)
- Failure in Duo module in v1.17.0 [\#126](https://github.com/venth/aws-adfs/issues/126)

**Merged pull requests:**

- lxml 4.4.0 dropped support for python 3.4 [\#130](https://github.com/venth/aws-adfs/pull/130) ([pdecat](https://github.com/pdecat))
- Use MozillaCookieJar to support cookies with "expires" far in the future on Windows [\#129](https://github.com/venth/aws-adfs/pull/129) ([pdecat](https://github.com/pdecat))
- Add FIDO/U2F support to Duo authentication [\#127](https://github.com/venth/aws-adfs/pull/127) ([pdecat](https://github.com/pdecat))

## [1.17.0](https://github.com/venth/aws-adfs/tree/1.17.0) (2019-07-11)

[Full Changelog](https://github.com/venth/aws-adfs/compare/v1.16.0...1.17.0)

**Merged pull requests:**

- Handle sspi like other config options [\#125](https://github.com/venth/aws-adfs/pull/125) ([kfattig](https://github.com/kfattig))
- Add support for AzureMfaAuthentication [\#124](https://github.com/venth/aws-adfs/pull/124) ([mjernsell](https://github.com/mjernsell))

## [v1.16.0](https://github.com/venth/aws-adfs/tree/v1.16.0) (2019-06-04)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.15.0...v1.16.0)

**Merged pull requests:**

- Respect AWS\_DEFAULT\_PROFILE if defined [\#122](https://github.com/venth/aws-adfs/pull/122) ([rinrinne](https://github.com/rinrinne))

## [1.15.0](https://github.com/venth/aws-adfs/tree/1.15.0) (2019-04-25)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.14.0...1.15.0)

**Merged pull requests:**

- Add support for adfs-ca-bundle option [\#120](https://github.com/venth/aws-adfs/pull/120) ([budzejko](https://github.com/budzejko))

## [1.14.0](https://github.com/venth/aws-adfs/tree/1.14.0) (2019-04-20)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.13.0...1.14.0)

**Implemented enhancements:**

- Feature request for more authentication methods [\#53](https://github.com/venth/aws-adfs/issues/53)

**Merged pull requests:**

- save provider\_id config [\#121](https://github.com/venth/aws-adfs/pull/121) ([tommywo](https://github.com/tommywo))
- Fix Duo authentication initiation failure messages [\#119](https://github.com/venth/aws-adfs/pull/119) ([pdecat](https://github.com/pdecat))

## [1.13.0](https://github.com/venth/aws-adfs/tree/1.13.0) (2019-02-23)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.12.3...1.13.0)

**Merged pull requests:**

- Add support for Azure MFA Server [\#117](https://github.com/venth/aws-adfs/pull/117) ([0x91](https://github.com/0x91))

## [1.12.3](https://github.com/venth/aws-adfs/tree/1.12.3) (2019-01-23)

[Full Changelog](https://github.com/venth/aws-adfs/compare/1.12.2...1.12.3)

**Merged pull requests:**

- Fallback on prompt if env, stdin or auth file do not provide both username and password [\#115](https://github.com/venth/aws-adfs/pull/115) ([pdecat](https://github.com/pdecat))
- Save duo session cookies [\#111](https://github.com/venth/aws-adfs/pull/111) ([NotMrSteve](https://github.com/NotMrSteve))

## [1.12.2](https://github.com/venth/aws-adfs/tree/1.12.2) (2018-09-19)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.12.1...1.12.2)

**Closed issues:**

- Duo Authentication Issue [\#105](https://github.com/venth/aws-adfs/issues/105)

**Merged pull requests:**

- Corrected the XPath expression to work with the latest version of AWS… [\#107](https://github.com/venth/aws-adfs/pull/107) ([jan-molak](https://github.com/jan-molak))

## [0.12.1](https://github.com/venth/aws-adfs/tree/0.12.1) (2018-08-25)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.12.0...0.12.1)

**Closed issues:**

- Error: Python has stopped working when running aws-adfs [\#104](https://github.com/venth/aws-adfs/issues/104)
- Using the environment and stdin parameters [\#91](https://github.com/venth/aws-adfs/issues/91)

**Merged pull requests:**

- Fix Duo API change - follow result\_url and return cookie from result [\#106](https://github.com/venth/aws-adfs/pull/106) ([bghinkle](https://github.com/bghinkle))

## [0.12.0](https://github.com/venth/aws-adfs/tree/0.12.0) (2018-07-05)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.11.1...0.12.0)

**Closed issues:**

- Default Profile [\#86](https://github.com/venth/aws-adfs/issues/86)

**Merged pull requests:**

- Add RSA SecurID MFA [\#101](https://github.com/venth/aws-adfs/pull/101) ([NotMrSteve](https://github.com/NotMrSteve))
- Added flag for disabling Kerberos SSO authentication via SSPI [\#97](https://github.com/venth/aws-adfs/pull/97) ([JLambeth](https://github.com/JLambeth))

## [0.11.1](https://github.com/venth/aws-adfs/tree/0.11.1) (2018-06-20)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.11.0...0.11.1)

**Closed issues:**

- Symantec VIP has obfuscated form [\#93](https://github.com/venth/aws-adfs/issues/93)

**Merged pull requests:**

- login.py [\#99](https://github.com/venth/aws-adfs/pull/99) ([leonardo-test](https://github.com/leonardo-test))
- Fix Symantec VIP adapter [\#96](https://github.com/venth/aws-adfs/pull/96) ([avoidik](https://github.com/avoidik))

## [0.11.0](https://github.com/venth/aws-adfs/tree/0.11.0) (2018-05-10)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.10.1...0.11.0)

**Implemented enhancements:**

- Incorporating the new CLI/API session duration functionality [\#82](https://github.com/venth/aws-adfs/issues/82)

**Merged pull requests:**

- Allow to specify SAML response from local file [\#92](https://github.com/venth/aws-adfs/pull/92) ([avoidik](https://github.com/avoidik))

## [0.10.1](https://github.com/venth/aws-adfs/tree/0.10.1) (2018-04-14)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.10.0...0.10.1)

## [0.10.0](https://github.com/venth/aws-adfs/tree/0.10.0) (2018-04-14)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.9.1...0.10.0)

**Merged pull requests:**

- Change default profile to default [\#89](https://github.com/venth/aws-adfs/pull/89) ([KyleJamesWalker](https://github.com/KyleJamesWalker))
- Feature/read username and password from file [\#88](https://github.com/venth/aws-adfs/pull/88) ([keirwhitlock](https://github.com/keirwhitlock))

## [0.9.1](https://github.com/venth/aws-adfs/tree/0.9.1) (2018-04-09)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.9.0...0.9.1)

**Merged pull requests:**

- Allow phone call authentication [\#83](https://github.com/venth/aws-adfs/pull/83) ([KyleJamesWalker](https://github.com/KyleJamesWalker))

## [0.9.0](https://github.com/venth/aws-adfs/tree/0.9.0) (2018-04-08)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.8.0...0.9.0)

**Closed issues:**

- Requirements? botocore, boto3, and awscli downgrades? [\#75](https://github.com/venth/aws-adfs/issues/75)

## [0.8.0](https://github.com/venth/aws-adfs/tree/0.8.0) (2018-03-01)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.7.0...0.8.0)

**Implemented enhancements:**

- Support for Duo's "Remember Me" feature [\#40](https://github.com/venth/aws-adfs/issues/40)
- Allow selection of a device for second authentication factor in duo security integration when the preferred device setting is missing [\#33](https://github.com/venth/aws-adfs/issues/33)

**Fixed bugs:**

- adfs conflicts with default profile  [\#37](https://github.com/venth/aws-adfs/issues/37)

**Merged pull requests:**

- --printenv command line option [\#76](https://github.com/venth/aws-adfs/pull/76) ([jimweller](https://github.com/jimweller))

## [0.7.0](https://github.com/venth/aws-adfs/tree/0.7.0) (2018-02-16)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.6.1...0.7.0)

**Implemented enhancements:**

- How to use "role-arn" parameter? [\#70](https://github.com/venth/aws-adfs/issues/70)

## [0.6.1](https://github.com/venth/aws-adfs/tree/0.6.1) (2018-02-07)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.6.0...0.6.1)

## [0.6.0](https://github.com/venth/aws-adfs/tree/0.6.0) (2018-01-30)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.5.0...0.6.0)

**Merged pull requests:**

- Add support for Ansible Tower/AWX workflow authentication [\#71](https://github.com/venth/aws-adfs/pull/71) ([zanettibo](https://github.com/zanettibo))

## [0.5.0](https://github.com/venth/aws-adfs/tree/0.5.0) (2018-01-27)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.4.8...0.5.0)

**Implemented enhancements:**

- Role arn passed as parameter to the login method [\#66](https://github.com/venth/aws-adfs/issues/66)

**Closed issues:**

- botocore VersionConflict issue [\#68](https://github.com/venth/aws-adfs/issues/68)

**Merged pull requests:**

- Role arn as parameter [\#67](https://github.com/venth/aws-adfs/pull/67) ([giafar](https://github.com/giafar))

## [0.4.8](https://github.com/venth/aws-adfs/tree/0.4.8) (2018-01-03)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.4.7...0.4.8)

**Closed issues:**

- aws-adfs installs with botocore-1.8.15, but requires botocore-1.8.17? both? [\#65](https://github.com/venth/aws-adfs/issues/65)

## [0.4.7](https://github.com/venth/aws-adfs/tree/0.4.7) (2017-12-24)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.4.6...0.4.7)

## [0.4.6](https://github.com/venth/aws-adfs/tree/0.4.6) (2017-12-24)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.4.5...0.4.6)

**Closed issues:**

- Bump awscli and botocore versions [\#64](https://github.com/venth/aws-adfs/issues/64)

## [0.4.5](https://github.com/venth/aws-adfs/tree/0.4.5) (2017-12-17)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.4.4...0.4.5)

**Closed issues:**

- Bump awscli  to 1.12.2 [\#62](https://github.com/venth/aws-adfs/issues/62)
- Bump to botocore==1.8.2 [\#61](https://github.com/venth/aws-adfs/issues/61)

## [0.4.4](https://github.com/venth/aws-adfs/tree/0.4.4) (2017-11-28)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.4.3...0.4.4)

**Fixed bugs:**

- Version 0.3.9 returns no roles [\#50](https://github.com/venth/aws-adfs/issues/50)

**Closed issues:**

- SSL certificate verify failed even with --no-ssl-verification [\#59](https://github.com/venth/aws-adfs/issues/59)

## [0.4.3](https://github.com/venth/aws-adfs/tree/0.4.3) (2017-11-02)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.4.2...0.4.3)

## [0.4.2](https://github.com/venth/aws-adfs/tree/0.4.2) (2017-11-02)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.4.1...0.4.2)

**Merged pull requests:**

- Fix Negotiate auth on non-domain-joined Windows hosts [\#58](https://github.com/venth/aws-adfs/pull/58) ([brandond](https://github.com/brandond))

## [0.4.1](https://github.com/venth/aws-adfs/tree/0.4.1) (2017-10-17)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.4.0...0.4.1)

## [0.4.0](https://github.com/venth/aws-adfs/tree/0.4.0) (2017-10-12)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.18...0.4.0)

**Fixed bugs:**

- When using two roles error: This account does not have access to any roles [\#55](https://github.com/venth/aws-adfs/issues/55)

**Merged pull requests:**

- Add Symantec VIP Access support [\#56](https://github.com/venth/aws-adfs/pull/56) ([irgeek](https://github.com/irgeek))

## [0.3.18](https://github.com/venth/aws-adfs/tree/0.3.18) (2017-10-06)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.17...0.3.18)

## [0.3.17](https://github.com/venth/aws-adfs/tree/0.3.17) (2017-10-05)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.16...0.3.17)

## [0.3.16](https://github.com/venth/aws-adfs/tree/0.3.16) (2017-10-04)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.15...0.3.16)

## [0.3.15](https://github.com/venth/aws-adfs/tree/0.3.15) (2017-10-04)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.14...0.3.15)

**Implemented enhancements:**

- When logging in with aws-adfs and Duo MFA [\#34](https://github.com/venth/aws-adfs/issues/34)

## [0.3.14](https://github.com/venth/aws-adfs/tree/0.3.14) (2017-09-19)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.13...0.3.14)

**Implemented enhancements:**

- Dependency incompatibility with botocore 1.6.0+ [\#52](https://github.com/venth/aws-adfs/issues/52)

## [0.3.13](https://github.com/venth/aws-adfs/tree/0.3.13) (2017-09-17)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.12...0.3.13)

## [0.3.12](https://github.com/venth/aws-adfs/tree/0.3.12) (2017-08-14)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.11...0.3.12)

**Implemented enhancements:**

- Introduce git tag based versioning [\#47](https://github.com/venth/aws-adfs/issues/47)

## [0.3.11](https://github.com/venth/aws-adfs/tree/0.3.11) (2017-08-13)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.9...0.3.11)

**Fixed bugs:**

- Upgrade from 0.3.6 to 0.3.7 breaking simple authentication [\#49](https://github.com/venth/aws-adfs/issues/49)

## [0.3.9](https://github.com/venth/aws-adfs/tree/0.3.9) (2017-07-28)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.8...0.3.9)

## [0.3.8](https://github.com/venth/aws-adfs/tree/0.3.8) (2017-07-20)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.7...0.3.8)

**Implemented enhancements:**

- ADFS with DUO list account alias instead of account IDs [\#35](https://github.com/venth/aws-adfs/issues/35)

## [0.3.7](https://github.com/venth/aws-adfs/tree/0.3.7) (2017-07-11)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.6...0.3.7)

**Implemented enhancements:**

- Script-ability [\#45](https://github.com/venth/aws-adfs/issues/45)

## [0.3.6](https://github.com/venth/aws-adfs/tree/0.3.6) (2017-06-24)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.5...0.3.6)

**Fixed bugs:**

- Version 0.3.4 returns no roles. [\#44](https://github.com/venth/aws-adfs/issues/44)

**Merged pull requests:**

- add login argument to accept username/password from stdin [\#48](https://github.com/venth/aws-adfs/pull/48) ([eikenb](https://github.com/eikenb))

## [0.3.5](https://github.com/venth/aws-adfs/tree/0.3.5) (2017-06-21)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.4...0.3.5)

**Fixed bugs:**

- Python 3 compatible? [\#41](https://github.com/venth/aws-adfs/issues/41)

## [0.3.4](https://github.com/venth/aws-adfs/tree/0.3.4) (2017-06-20)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.3...0.3.4)

**Implemented enhancements:**

- Duo Authentication fails for users who don't have a preferred Auth method. [\#30](https://github.com/venth/aws-adfs/issues/30)

**Fixed bugs:**

- Parsing error while trying to login to Duo MFA [\#42](https://github.com/venth/aws-adfs/issues/42)
- --region and --output-format flags don't seem to be working [\#27](https://github.com/venth/aws-adfs/issues/27)

**Closed issues:**

- Issues with Centos 7 [\#39](https://github.com/venth/aws-adfs/issues/39)
- TypeError [\#32](https://github.com/venth/aws-adfs/issues/32)
- aws-adfs not working on macOS Sierra - System-installed Python 2.7 [\#31](https://github.com/venth/aws-adfs/issues/31)
- On login, skipping profile option causes error. [\#28](https://github.com/venth/aws-adfs/issues/28)

**Merged pull requests:**

- \#42 - Bug in parsing Duo host and signature, backwards compatible [\#43](https://github.com/venth/aws-adfs/pull/43) ([AndrewFarley](https://github.com/AndrewFarley))
- Update README.md [\#38](https://github.com/venth/aws-adfs/pull/38) ([wiederhold](https://github.com/wiederhold))
- Fix formatting in README.md [\#29](https://github.com/venth/aws-adfs/pull/29) ([roblugton](https://github.com/roblugton))

## [0.3.3](https://github.com/venth/aws-adfs/tree/0.3.3) (2017-04-12)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.2...0.3.3)

## [0.3.2](https://github.com/venth/aws-adfs/tree/0.3.2) (2017-04-09)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.1...0.3.2)

**Fixed bugs:**

- UnicodeEncodeError: 'ascii' codec can't encode character u'\u201c' in position 18498: ordinal not in range\(128\) [\#25](https://github.com/venth/aws-adfs/issues/25)

**Closed issues:**

- Add option to remove adfs Cookie that stores user account information [\#26](https://github.com/venth/aws-adfs/issues/26)

## [0.3.1](https://github.com/venth/aws-adfs/tree/0.3.1) (2017-04-04)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.3.0...0.3.1)

**Closed issues:**

- Failed with DUO MFA enabled.  [\#24](https://github.com/venth/aws-adfs/issues/24)

## [0.3.0](https://github.com/venth/aws-adfs/tree/0.3.0) (2017-03-27)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.2.3...0.3.0)

**Closed issues:**

- --verbose flag fails when used with login --adfs-host. [\#23](https://github.com/venth/aws-adfs/issues/23)
- Requests specifying Server Side Encryption with AWS KMS managed keys require AWS Signature Version 4 [\#22](https://github.com/venth/aws-adfs/issues/22)

## [0.2.3](https://github.com/venth/aws-adfs/tree/0.2.3) (2017-03-04)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.2.2...0.2.3)

**Closed issues:**

- list output is too simple [\#20](https://github.com/venth/aws-adfs/issues/20)

## [0.2.2](https://github.com/venth/aws-adfs/tree/0.2.2) (2017-03-01)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.2.1...0.2.2)

**Closed issues:**

- Ability to change the URN in html\_roles\_fetcher.py [\#18](https://github.com/venth/aws-adfs/issues/18)

## [0.2.1](https://github.com/venth/aws-adfs/tree/0.2.1) (2017-02-16)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.2.0...0.2.1)

**Closed issues:**

- Add an option to change the STS token duration [\#17](https://github.com/venth/aws-adfs/issues/17)

**Merged pull requests:**

- Added extra option "--provider-id"  [\#19](https://github.com/venth/aws-adfs/pull/19) ([keirwhitlock](https://github.com/keirwhitlock))

## [0.2.0](https://github.com/venth/aws-adfs/tree/0.2.0) (2016-11-05)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.1.5...0.2.0)

**Closed issues:**

- automate aws-adfs with expect [\#16](https://github.com/venth/aws-adfs/issues/16)

**Merged pull requests:**

- Default to 'default' profile, in line with other AWS tools. [\#14](https://github.com/venth/aws-adfs/pull/14) ([brandond](https://github.com/brandond))

## [0.1.5](https://github.com/venth/aws-adfs/tree/0.1.5) (2016-10-11)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.1.4...0.1.5)

**Merged pull requests:**

- Improve handling of errors caused by excessive cookie growth. [\#15](https://github.com/venth/aws-adfs/pull/15) ([brandond](https://github.com/brandond))

## [0.1.4](https://github.com/venth/aws-adfs/tree/0.1.4) (2016-10-04)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.1.3...0.1.4)

**Merged pull requests:**

- Improve handling of role selection [\#13](https://github.com/venth/aws-adfs/pull/13) ([brandond](https://github.com/brandond))

## [0.1.3](https://github.com/venth/aws-adfs/tree/0.1.3) (2016-08-30)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.1.2...0.1.3)

**Closed issues:**

- requests.exceptions.SSLError: \[Errno 2\] - aws-adfs version 0.1.1 [\#11](https://github.com/venth/aws-adfs/issues/11)

**Merged pull requests:**

- Move pytest-runner out of setup-requires [\#12](https://github.com/venth/aws-adfs/pull/12) ([brandond](https://github.com/brandond))

## [0.1.2](https://github.com/venth/aws-adfs/tree/0.1.2) (2016-08-27)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.1.1...0.1.2)

## [0.1.1](https://github.com/venth/aws-adfs/tree/0.1.1) (2016-08-18)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.1.0...0.1.1)

**Merged pull requests:**

- ssl\_verification must be a str [\#10](https://github.com/venth/aws-adfs/pull/10) ([brandond](https://github.com/brandond))

## [0.1.0](https://github.com/venth/aws-adfs/tree/0.1.0) (2016-08-14)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.0.9...0.1.0)

**Merged pull requests:**

- Add support for Kerberos SSO on Windows via requests\_negotiate\_sspi [\#9](https://github.com/venth/aws-adfs/pull/9) ([brandond](https://github.com/brandond))

## [0.0.9](https://github.com/venth/aws-adfs/tree/0.0.9) (2016-07-22)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.0.8...0.0.9)

**Closed issues:**

- Ability to add environment variables [\#8](https://github.com/venth/aws-adfs/issues/8)
- UnicodeEncodeError: 'ascii' codec can't encode character u'\u017a' in position 705: ordinal not in range\(128\) [\#6](https://github.com/venth/aws-adfs/issues/6)

**Merged pull requests:**

- Python 3 compat [\#7](https://github.com/venth/aws-adfs/pull/7) ([brandond](https://github.com/brandond))

## [0.0.8](https://github.com/venth/aws-adfs/tree/0.0.8) (2016-07-19)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.0.7...0.0.8)

**Closed issues:**

- Clear IAM role from config [\#5](https://github.com/venth/aws-adfs/issues/5)

## [0.0.7](https://github.com/venth/aws-adfs/tree/0.0.7) (2016-07-12)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.0.6...0.0.7)

**Merged pull requests:**

- Store last username in profile config; use it as default for prompt. [\#4](https://github.com/venth/aws-adfs/pull/4) ([brandond](https://github.com/brandond))

## [0.0.6](https://github.com/venth/aws-adfs/tree/0.0.6) (2016-07-10)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.0.5...0.0.6)

**Merged pull requests:**

- Add support for legacy aws\_security\_token key in credentials file [\#3](https://github.com/venth/aws-adfs/pull/3) ([brandond](https://github.com/brandond))

## [0.0.5](https://github.com/venth/aws-adfs/tree/0.0.5) (2016-07-10)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.0.4...0.0.5)

**Closed issues:**

- Runnable script instruction [\#1](https://github.com/venth/aws-adfs/issues/1)

**Merged pull requests:**

- Remove storage of credentials, in favor of storing ADFS session cookies. [\#2](https://github.com/venth/aws-adfs/pull/2) ([brandond](https://github.com/brandond))

## [0.0.4](https://github.com/venth/aws-adfs/tree/0.0.4) (2016-07-08)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.0.3...0.0.4)

## [0.0.3](https://github.com/venth/aws-adfs/tree/0.0.3) (2016-06-25)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.0.2...0.0.3)

## [0.0.2](https://github.com/venth/aws-adfs/tree/0.0.2) (2016-06-25)

[Full Changelog](https://github.com/venth/aws-adfs/compare/0.0.1...0.0.2)

## [0.0.1](https://github.com/venth/aws-adfs/tree/0.0.1) (2016-06-25)

[Full Changelog](https://github.com/venth/aws-adfs/compare/73cdbeb2e6c78c00897a7ea68cbca1fd19f5669e...0.0.1)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
