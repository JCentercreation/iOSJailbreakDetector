# iOSJailbreakDetector

**Swift Package Manager** • **iOS 12+** • **App Store Safe** • **MIT License**

Multi-layered jailbreak detection library for iOS applications. Implements 8 independent detection vectors with confidence scoring and timing-based evasion resistance.

## Overview

`iOSJailbreakDetector` provides production-ready jailbreak detection suitable for App Store distribution. Key features include:

- 8 orthogonal detection methods (files, DYLD, sandbox, environment)
- Confidence scoring (0.0-1.0) based on detection ratio
- Timing analysis for runtime hooking detection
- Granular indicator reporting for security forensics
- `@MainActor` thread safety
- No private APIs (POSIX + Foundation only)

## Requirements

| Platform | Minimum Version |
|----------|-----------------|
| iOS | 12.0+ |
| Xcode | 15.0+ |
| Swift | 5.9+ |

**Dependencies:** `UIKit`, `Darwin`

## Installation

### Swift Package Manager

Add to `Package.swift`:
```swift
dependencies: [ .package(url: “https://github.com/jcentercreation/iOSJailbreakDetector.git”, from: “1.0.0”) ]
```

### Xcode

1. File → Add Package Dependencies
2. Enter package URL: `https://github.com/[your-username]/iOSJailbreakDetector.git`
3. Select version rule: "Up to Next Major Version"

## Usage

### Basic Detection
```swift
import iOSJailbreakDetector import OSLog
let detector = iOSJailbreakDetector.shared let result = detector.detectJailbreak()
if result.isJailBroken && result.estimatedConfidenceLevel > 0.5 { Logger.security.error( “”” Jailbreak detected: result.jailbreakDetectionIndicator.map { “$0)” }) Confidence: $$result.estimatedConfidenceLevel, format: .percent) “”” ) // Implement security measures } else { Logger.security.info(“Device verified clean”) }
```

### Advanced Timing Analysis
```swift
// File existence with hooking detection let fileResult = detector.checkSuspiciousFilesWithTiming( path: “/Applications/Cydia.app”, suspiciousJailbreakHookTimingInSeconds: 0.05 )
switch fileResult { case .jailbroken(let time, let path): Logger.security.error(“Jailbreak artifact: time * 1000, specifier: “%.1f”)]ms”) case .suspicious(let delay, let path): Logger.security.warning(“Runtime hooking: delay * 1000, specifier: “%.1f”)]ms delay”) case .clean: break }
```

## Detection Methods

| Method | Technique | Reliability |
|--------|-----------|-------------|
| URL Schemes | `UIApplication.shared.canOpenURL` | Low* |
| Suspicious Files | `FileManager` + `access()` | High |
| Sandbox Violations | Write `/private/` | Medium |
| DYLD Injection | `dlopen()` probing | High |
| Process Tracing | `sysctl()` `P_TRACED` | Medium |
| Symbolic Links | `attributesOfItem` | Low |
| Fork Testing | `posix_spawn()` | Medium |
| Environment | `getenv()` | High |

_*App Store apps cannot detect jailbreak URL schemes due to sandboxing_

## API Reference

### Core

- **`detectJailbreak() → JailbreakDetectionResult`**
  Single call executing all 8 detection vectors

### Granular Checks

- `checkSuspiciousFilesWithTiming(path:suspiciousJailbreakHookTimingInSeconds:) → SuspiciousFilesWithTimingResult`
- `checkDYLDInjectionWithTiming(library:timeoutSeconds:) → DYLDInjectionResult`
- `checkSuspiciousFiles(path:) → Bool`
- `checkDYLDInjection(library:) → Bool`
- `checkURLScheme(urlScheme:) → Bool`

### Result Types

- `JailbreakDetectionResult`
- `JailbreakDetectionIndicators : CaseIterable`
- `SuspiciousFilesWithTimingResult`
- `DYLDInjectionResult`

## Security Recommendations

1. **Threshold**: Require `confidence > 0.375` (3/8 indicators)
2. **Periodic**: Re-run every 30-60 seconds via background tasks
3. **Layered**: Combine with DeviceCheck server attestation
4. **Obfuscation**: Runtime-decode paths/libraries
5. **Response**: Graceful degradation over app termination

## Limitations

- **Rootless jailbreaks** (Dopamine, palera1n) evade traditional file paths
- **Runtime hooks** (Shadow, Choicy) may intercept syscalls
- **Enterprise builds** bypass URL scheme restrictions
- **Static analysis** reveals detection logic

## Optional Configuration

### Info.plist (URL Schemes)
LSApplicationQueriesSchemes cydia filza sileo

## License

MIT License © 2025
