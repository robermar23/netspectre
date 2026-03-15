# Changelog

## [1.17.0](https://github.com/robermar23/netspectre/compare/v1.16.0...v1.17.0) (2026-03-15)


### Features

* **proxy, sitemap:** add "Probe in Network" functionality to resolve hostnames and update network workspace ([e093cef](https://github.com/robermar23/netspectre/commit/e093cef6485eb92264f92e492a73d85504124cea))
* **scanner:** add modules for vulnerability scanning including broken authentication, command injection, CORS misconfiguration, insecure deserialization, and enhance IPC channels for scanner control ([2a2d715](https://github.com/robermar23/netspectre/commit/2a2d7156818f06b30eead64101336f0a00497dc8))
* **scanner:** add SSRF, XSS, and XXE scanning modules ([5f8c678](https://github.com/robermar23/netspectre/commit/5f8c678acb04af1d2142415ad48fa91acc23b6a3))
* **scanner:** implement active vulnerability scanner functionality and IPC handlers ([e2f5361](https://github.com/robermar23/netspectre/commit/e2f5361122dc462be96d468c9f155e4fdce7ed9e))
* **scanner:** implement DNS resolution for hostname to IP conversion in network workspace ([8240fc3](https://github.com/robermar23/netspectre/commit/8240fc3f7c28bb4157129ac1fb6d431da1d14513))
* **scanner:** implement vulnerability scanner UI and functionality ([8855bc7](https://github.com/robermar23/netspectre/commit/8855bc78fe9ec0550026d857523a3c676f632f71))
* **scanner:** implement vulnerability scanner UI and functionality ([f05d4e8](https://github.com/robermar23/netspectre/commit/f05d4e8e84e0ae99e5b6b76fa3ca58307109098a))


### Bug Fixes

* **scanner:** improve error handling and enhance checkbox styling for scanner modules ([967fa51](https://github.com/robermar23/netspectre/commit/967fa51f465efbb482c7b8aae4ea6db51b151a75))

## [1.16.0](https://github.com/robermar23/netspectre/compare/v1.15.0...v1.16.0) (2026-03-15)


### Features

* **api:** add API detect complete channel and update IPC handlers ([7af5510](https://github.com/robermar23/netspectre/commit/7af551053f6b1d309ca08eafda0a9b09b3217707))
* **crawler:** add active and passive crawling features with tests ([2fd3039](https://github.com/robermar23/netspectre/commit/2fd3039c7f31ab5adf09f103a9902ee07def5af0))
* **proxy:** implement intercepting proxy features and related constants ([18bb3b9](https://github.com/robermar23/netspectre/commit/18bb3b9c6a931f097105763fd2bb549cb3bd3e58))
* **proxy:** implement intercepting proxy features and related constants ([818ff83](https://github.com/robermar23/netspectre/commit/818ff832ad489429d7ea1184339f8b08d9a72dd3))
* **sitemap:** enhance sitemap rendering with API badge and form handling improvements ([9a452a6](https://github.com/robermar23/netspectre/commit/9a452a642d089286b69e7bf3e743e36ada0b85d7))

## [1.15.0](https://github.com/robermar23/netspectre/compare/v1.14.0...v1.15.0) (2026-03-14)


### Features

* **cloudEnum:** add isCloudEnumRunning function and enhance IPC error handling for active sessions ([023ec1d](https://github.com/robermar23/netspectre/commit/023ec1d8d463a0ff063992a04e6dbdfdfce8d3bc))
* **cloudEnum:** Implement Container & Cloud Enumeration feature ([c906d85](https://github.com/robermar23/netspectre/commit/c906d856da7afb404979e7c01e2f68d1bbc881ab))
* **cloudEnum:** Implement Container & Cloud Enumeration feature ([f57bee6](https://github.com/robermar23/netspectre/commit/f57bee607f9795c3e2c4476a83035cfde6e2d8be))

## [1.14.0](https://github.com/robermar23/netspectre/compare/v1.13.0...v1.14.0) (2026-03-09)


### Features

* **shares:** add Impacket support and manual path overrides ([7cd5cd2](https://github.com/robermar23/netspectre/commit/7cd5cd2f83e8cf48151ace59eaf19407d7cd9159))


### Bug Fixes

* applied code review changes ([9f8b82d](https://github.com/robermar23/netspectre/commit/9f8b82d5c82758f7ed35f7f8e1a689be821a8bfe))
* bug hm-01 ([6e8173a](https://github.com/robermar23/netspectre/commit/6e8173ac7e3f1d9e1da98547711b50726be5f9d9))
* bug hm-02 ([1f3e0c9](https://github.com/robermar23/netspectre/commit/1f3e0c9423c157a609470fc18557ac87a73b1aa8))
* bug-hm-05 ([a25722c](https://github.com/robermar23/netspectre/commit/a25722c4eccf0e293c4e566a9f829b22b075a9bf))
* cred-01 ([08fd652](https://github.com/robermar23/netspectre/commit/08fd6529516936ba78cec5de965248f3bb9e3515))

## [1.13.0](https://github.com/robermar23/netspectre/compare/v1.12.0...v1.13.0) (2026-03-08)


### Features

* **credspray:** implement default credential spraying ([e91552b](https://github.com/robermar23/netspectre/commit/e91552bf73ca6782acad633d6734ef51d1b453ac))
* **credspray:** implement default credential spraying ([e56c6cc](https://github.com/robermar23/netspectre/commit/e56c6ccdfe2d47d363f9cda2d19b48c4041a5bee))


### Bug Fixes

* resolving broken tests ([e953e2b](https://github.com/robermar23/netspectre/commit/e953e2ba7951cb013dffd8889b4a6419bb453a4e))

## [1.12.0](https://github.com/robermar23/netspectre/compare/v1.11.0...v1.12.0) (2026-03-08)


### Features

* update docs ([cba866e](https://github.com/robermar23/netspectre/commit/cba866eb92235c5284b486f85405cea4e6e9ca77))

## [1.11.0](https://github.com/robermar23/netspectre/compare/v1.10.1...v1.11.0) (2026-03-07)


### Features

* **dir-fuzzer:** implement web directory fuzzer feature ([87d3394](https://github.com/robermar23/netspectre/commit/87d33945f62ab9a7b05a62beb48f0594a1ec2da2))
* Implement a comprehensive Electron application for network detection, scanning, analysis, and offensive security operations. ([6d3d478](https://github.com/robermar23/netspectre/commit/6d3d47845a1a074a34cae68abb9752a38cec5a31))
* **offense:** implement network share enumeration and browsing ([278b27a](https://github.com/robermar23/netspectre/commit/278b27a6c212f046c991d4b1de247d181e8e16ff))
* **pentest:** add Metasploit RPC integration (Phase 4B) ([cc90be6](https://github.com/robermar23/netspectre/commit/cc90be6b616400b5690cb69cc591ea2168cdf28a))
* **revshell:** implement automated reverse shell listener ([61522a7](https://github.com/robermar23/netspectre/commit/61522a7f751834a1038b89b07bba656b6d84585d))


### Bug Fixes

* fix tests from recent changes ([5d9cf9d](https://github.com/robermar23/netspectre/commit/5d9cf9d28740a06b40f1c3918a1a844b4c34e82c))

## [1.10.1](https://github.com/robermar23/netspectre/compare/v1.10.0...v1.10.1) (2026-02-28)


### Bug Fixes

* **main:** unify nmap detection and add platform-specific path fallbacks ([0aa5592](https://github.com/robermar23/netspectre/commit/0aa5592ed55b4c15719d855616f0b32e3b064194))
* **main:** unify nmap detection and add platform-specific path fallbacks ([a4b446f](https://github.com/robermar23/netspectre/commit/a4b446f482fe2b87f065afba541d0ffb49389c34))

## [1.10.0](https://github.com/robermar23/netspectre/compare/v1.9.0...v1.10.0) (2026-02-28)


### Features

* **snmp:** implement multi-phase intelligence gathering ([bdf19f2](https://github.com/robermar23/netspectre/commit/bdf19f26a5008f8e0e06cac46f32020386e748c2))
* **snmp:** implement multi-phase intelligence gathering ([0954ec5](https://github.com/robermar23/netspectre/commit/0954ec51c4e9b643172ca327ad8b3f5048b4b41b))

## [1.9.0](https://github.com/robermar23/netspectre/compare/v1.8.1...v1.9.0) (2026-02-28)


### Features

* **core:** implement SNMP walking, interactive topology map, and rog… ([93e3349](https://github.com/robermar23/netspectre/commit/93e3349282e2d7bfc30a154f601977dd5f53b526))
* **core:** implement SNMP walking, interactive topology map, and rogue DNS ([11681ba](https://github.com/robermar23/netspectre/commit/11681ba9728ba5246f6e17974c8596ddbab90e60))


### Bug Fixes

* enhanced images ([39b3fe5](https://github.com/robermar23/netspectre/commit/39b3fe52e60c9ac3daf7710ecc9db9aab158310b))
* snmp walk output format ([9eb6a11](https://github.com/robermar23/netspectre/commit/9eb6a1144782448a3b44304ec37666261e7745b7))

## [1.8.1](https://github.com/robermar23/netspectre/compare/v1.8.0...v1.8.1) (2026-02-27)


### Bug Fixes

* **ui:** dynamic dependency banner missing tshark ipc handler ([b64f7ed](https://github.com/robermar23/netspectre/commit/b64f7edcc3a69f0a8a53f51cdb8bded237b9481f))

## [1.8.0](https://github.com/robermar23/netspectre/compare/v1.7.1...v1.8.0) (2026-02-27)


### Features

* **scanner:** implement passive network intelligence suite ([45dc118](https://github.com/robermar23/netspectre/commit/45dc118c87354c265228b0705021094b67efcdc6))


### Bug Fixes

* **ui:** resolve manual testing bugs for passive intelligence ([324ffae](https://github.com/robermar23/netspectre/commit/324ffae602ec5784b743536306f1ea83f9aac869))

## [1.7.1](https://github.com/robermar23/netspectre/compare/v1.7.0...v1.7.1) (2026-02-26)


### Bug Fixes

* **main:** resolve MAC parsing and macOS tool detection ([3a2a3ba](https://github.com/robermar23/netspectre/commit/3a2a3ba0c0d95e1a070cf6f9b6ff1fb89c7cef84))

## [1.7.0](https://github.com/robermar23/netspectre/compare/v1.6.0...v1.7.0) (2026-02-26)


### Features

* add ci run that run all tests ([bf7c495](https://github.com/robermar23/netspectre/commit/bf7c4958b9c6e945c32adb048301599067f0bf73))


### Bug Fixes

* fix npm test command ([837d217](https://github.com/robermar23/netspectre/commit/837d217f06ad601e21cdc71375302a13347a5e38))

## [1.6.0](https://github.com/robermar23/netspectre/compare/v1.5.0...v1.6.0) (2026-02-26)


### Features

* Implement Tshark integration, settings management ([183a367](https://github.com/robermar23/netspectre/commit/183a367c30535fa0aa5196aa87a7b307e9da0931))
* Implement Tshark integration, settings management ([b3edd4f](https://github.com/robermar23/netspectre/commit/b3edd4f74b790ffd7915362afa814dfe9a6b4f96))


### Bug Fixes

* **renderer:** address XSS security vulnerabilities in index.js ([0152c27](https://github.com/robermar23/netspectre/commit/0152c2785e2cb2702ee95bbed1f51edd307997a4))
* **renderer:** replace unsafe innerHTML with DOM manipulation ([b30b6d7](https://github.com/robermar23/netspectre/commit/b30b6d70ac6e5ad49433374cc40fc3ca71053a0c))

## [1.5.0](https://github.com/robermar23/netspectre/compare/v1.4.3...v1.5.0) (2026-02-25)


### Features

* adjust status indicator placement and fix adding by subnet ([9de8d42](https://github.com/robermar23/netspectre/commit/9de8d423cb6d765f87580b9ef4d90777a8825cb2))
* allow nmap scan all from dashboard ([07a36a0](https://github.com/robermar23/netspectre/commit/07a36a012b06814413e159053e793c1409a20b54))
* Introduce Nmap XML parsing and a scan orchestrator to enable comprehensive network deep scanning. ([71f3537](https://github.com/robermar23/netspectre/commit/71f3537a661a1118505eb40ebab626854057719e))

## [1.4.3](https://github.com/robermar23/netspectre/compare/v1.4.2...v1.4.3) (2026-02-25)


### Bug Fixes

* put back dependences ([20d96ac](https://github.com/robermar23/netspectre/commit/20d96ac3fb5e0048632e9e3410e8c4665d555073))

## [1.4.2](https://github.com/robermar23/netspectre/compare/v1.4.1...v1.4.2) (2026-02-25)


### Bug Fixes

* ref to license file was wrong ([80ed80b](https://github.com/robermar23/netspectre/commit/80ed80be64420c2c447d6c2b5c3673a2cc004894))

## [1.4.1](https://github.com/robermar23/netspectre/compare/v1.4.0...v1.4.1) (2026-02-24)


### Bug Fixes

* fix build error for deb ([997e729](https://github.com/robermar23/netspectre/commit/997e729c227d7bc09a98030eb499b61d8d1ffe71))

## [1.4.0](https://github.com/robermar23/netspectre/compare/v1.3.1...v1.4.0) (2026-02-24)


### Features

* Implement main Electron process with network scanning, auto-upd… ([2537ecf](https://github.com/robermar23/netspectre/commit/2537ecfe8d62cf7453b9cf20eba775c1bb54f96a))
* Implement main Electron process with network scanning, auto-updates, IPC handlers, and enhanced Linux packaging configurations. ([47dfaf5](https://github.com/robermar23/netspectre/commit/47dfaf5809c4907c95f67bf4b11dff9e6148e5fd))

## [1.3.1](https://github.com/robermar23/netspectre/compare/v1.3.0...v1.3.1) (2026-02-23)


### Bug Fixes

* restore bad functionality ([5ddc8ae](https://github.com/robermar23/netspectre/commit/5ddc8aeb031a65daf5074006728b5528ccf2be55))

## [1.3.0](https://github.com/robermar23/netspectre/compare/v1.2.1...v1.3.0) (2026-02-23)


### Features

* Implement initial network detection and scanning capabilities i… ([812b069](https://github.com/robermar23/netspectre/commit/812b069bd0994224ef39d754aa5f5748e8024696))


### Bug Fixes

* addressed the remaining 6 warnings flagged by Sourcery AI! ([ba977be](https://github.com/robermar23/netspectre/commit/ba977be358240de4bbe4cc4fae08523568b2eba4))

## [1.2.1](https://github.com/robermar23/netspectre/compare/v1.2.0...v1.2.1) (2026-02-23)


### Bug Fixes

* add image log ([9154b64](https://github.com/robermar23/netspectre/commit/9154b6454aa85e3c53456ac63ea77da5f9a2b28e))
* add image log ([187a9f5](https://github.com/robermar23/netspectre/commit/187a9f5970990af08fdbf8b01b0369fe6ab45a3d))

## [1.2.0](https://github.com/robermar23/netspectre/compare/v1.1.1...v1.2.0) (2026-02-23)


### Features

* Add application logo and icons, and update README and favicon links. ([919326c](https://github.com/robermar23/netspectre/commit/919326c8f8395960ff4b8204142122c7fadbeb2e))

## [1.1.1](https://github.com/robermar23/network-detection/compare/v1.1.0...v1.1.1) (2026-02-23)


### Bug Fixes

* update node ver ([d836d41](https://github.com/robermar23/network-detection/commit/d836d413e534754de67a54367d44ff97b220e14f))

## [1.1.0](https://github.com/robermar23/network-detection/compare/v1.0.2...v1.1.0) (2026-02-23)


### Features

* install options for windows setup ([c0fa755](https://github.com/robermar23/network-detection/commit/c0fa7551b7c50bfaf79e9cae80cfa2a8f0217556))


### Bug Fixes

* path wrong for release main page ([54b79fb](https://github.com/robermar23/network-detection/commit/54b79fbdd8f5d1ac76a224411c3af9be750855d0))

## [1.0.2](https://github.com/robermar23/network-detection/compare/v1.0.1...v1.0.2) (2026-02-23)


### Bug Fixes

* make sure we set releaeType so assets are actually published ([cc1a3c0](https://github.com/robermar23/network-detection/commit/cc1a3c06e3f72333c2b40fe7fefa2397acb4bcaa))

## [1.0.1](https://github.com/robermar23/network-detection/compare/v1.0.0...v1.0.1) (2026-02-23)


### Bug Fixes

* merge release automation into a single action ([cd3d3d6](https://github.com/robermar23/network-detection/commit/cd3d3d69c9c5d39fe27e1ed4dfa0f0b4f22bfe89))

## 1.0.0 (2026-02-22)


### Features

* Add comprehensive development rules for the Electron desktop application agent. ([6b71674](https://github.com/robermar23/network-detection/commit/6b71674bd1a47f2aea8f740b5399d999febe277a))
* Add Electron build and release configurations, CI/CD workflows ([fe142c9](https://github.com/robermar23/network-detection/commit/fe142c9eb2b5bd8c7289f4601e7bbcf1e2deeb21))
* Add initial project license and comprehensive README documentation. ([1346a60](https://github.com/robermar23/network-detection/commit/1346a6091d7239912fc7235258ada4a4f153a93b))
* Implement initial Electron application structure with a network detection dashboard and IPC communication. ([9c0e911](https://github.com/robermar23/network-detection/commit/9c0e9113f8c6610ec0da3931933a5017137cea20))
* Implement initial Electron application structure, rename project to NetSpecter, and add core main/renderer process logic for network scanning UI. ([98925c9](https://github.com/robermar23/network-detection/commit/98925c9c82bc2397c6c13de8f5dfcc4509e5e565))
* Implement initial renderer process for network detection UI with host display, deep scan, and interface management. ([aca8ed1](https://github.com/robermar23/network-detection/commit/aca8ed1881cfcd8b72b14d89cd8a0e46c622917e))
* Implement NetSpecter network detection application with core scanning, deep scanning, and Nmap orchestration. ([bbb3a51](https://github.com/robermar23/network-detection/commit/bbb3a51754da4aed0cca02759bb0afc09fa07c5b))
* Implement Nmap integration and establish the core Electron application structure. ([5f99b3c](https://github.com/robermar23/network-detection/commit/5f99b3c8852cf2bfb7f6555a02af467ed58dab6a))
* Initialize Electron main process, window management, and IPC communication channels. ([5a81064](https://github.com/robermar23/network-detection/commit/5a81064c3c303cec1eb1eba7b3398e41cc265b11))
* Integrate Nmap for advanced network scanning, host detail enrichment, and Ncat support. ([316530f](https://github.com/robermar23/network-detection/commit/316530f6cfa23e9d16ae373cfbc33e5d253a1d9c))
* Introduce a new network detection user interface with host display, filtering, sorting, detailed views, and deep scan result integration. ([60ff664](https://github.com/robermar23/network-detection/commit/60ff6644dc3363375f78682a6d6cd770d9eb46e1))
* Introduce core network and deep scanning capabilities with Electron IPC, auto-updater, external action integration, and result management. ([e1fdaa9](https://github.com/robermar23/network-detection/commit/e1fdaa9b06babaecc038c1171cc11c4e8c233e0a))
* introduce deep network scanning with port enumeration, service identification, TLS analysis, and security auditing capabilities. ([6598c61](https://github.com/robermar23/network-detection/commit/6598c617633ab18d99c1b708f02bfbf0ba10181c))
* Introduce NetSpecter dashboard UI with network scanning controls, host display, and interactive rendering logic. ([47979b7](https://github.com/robermar23/network-detection/commit/47979b7f316f621102dc5400c5ede9a3f7ff09b9))
* Set up the initial Electron application structure, including UI, main process, and modules for network and deep scanning. ([2ed8835](https://github.com/robermar23/network-detection/commit/2ed8835a6a3e9039b54533e08cad0945da51caa4))


### Bug Fixes

* grabbing metadata from scan results ([7329f3c](https://github.com/robermar23/network-detection/commit/7329f3c243e846933cc670ac2f1a0f1efa0d405b))
