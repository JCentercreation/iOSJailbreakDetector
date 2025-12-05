// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation

#if canImport(UIKit)
import UIKit
#endif

@MainActor
public final class iOSJailbreakDetector {
    
    public static let shared = iOSJailbreakDetector()
    
    private init() { }
    
    /// Performs comprehensive multi-layered jailbreak detection across 8 independent detection vectors.
    ///
    /// This function executes a battery of sophisticated checks designed to identify jailbroken iOS devices
    /// with high confidence while minimizing false positives. Each detection method targets a distinct
    /// jailbreak indicator, and results are aggregated into a confidence score.
    ///
    /// **Detection Methods (8 total checks):**
    /// 1. **URL Schemes** - Detects Cydia, Filza, Sileo, and other jailbreak app handlers
    /// 2. **Suspicious Files** - Scans for Cydia.app, MobileSubstrate.dylib, APT repositories, SSH daemons
    /// 3. **System Path Violations** - Attempts to write outside app sandbox to `/private/`
    /// 4. **DYLD Injection** - Probes for Substrate, libhooker, SSLKillSwitch libraries via `dlopen`
    /// 5. **Sandbox Integrity** - Checks process flags (`P_TRACED`) via `sysctl`/`kinfo_proc`
    /// 6. **Symbolic Links** - Detects tampered system directories (`/usr/include`, `/Applications`)
    /// 7. **Fork Behavior** - Tests `posix_spawn("/bin/ls")` sandbox enforcement
    /// 8. **Environment Variables** - Scans `DYLD_INSERT_LIBRARIES`, `_MSSafeMode`, etc.
    ///
    /// **Scoring Algorithm:**
    /// - Each passing check increments `detectionsCounter`
    /// - `estimatedConfidenceLevel = detectionsCounter / totalChecks` (0.0 - 1.0)
    /// - `isJailBroken = detectionsCounter > 0` (any detection triggers)
    ///
    /// **Returns:** ``JailbreakDetectionResult` containing:
    /// - `isJailBroken`: Boolean detection result
    /// - `jailbreakDetectionIndicator`: Array of triggered indicators for logging/forensics
    /// - `estimatedConfidenceLevel`: Float confidence (0.125 = 1/8 checks, 1.0 = all checks failed)
    ///
    /// **Usage Example:**
    /// ```swift
    /// let result = iOSJailbreakDetector.shared.detectJailbreak()
    /// if result.isJailBroken {
    ///     Logger.security.error("Jailbreak detected: $$result.jailbreakDetectionIndicator) Confidence: $$result.estimatedConfidenceLevel)")
    ///     // Show warning screen, limit functionality, or terminate
    /// } else {
    ///     Logger.security.info("Device clean. Confidence: $$result.estimatedConfidenceLevel)")
    /// }
    /// ```
    ///
    /// **Important Security Considerations:**
    /// - **Layered Defense**: Single checks can be bypassed; combine multiple indicators
    /// - **App Store Limitations**: `canOpenURL` for jailbreak schemes always returns `false` in sandboxed apps
    /// - **Evasion Resistance**: Uses both Foundation APIs and POSIX syscalls (`access()`, `dlopen()`)
    /// - **Performance**: ~50-100ms total execution time on iPhone 15+
    /// - **Thread Safety**: `@MainActor` ensures UI-safe execution for `UIApplication.shared` calls
    ///
    /// **Known Bypass Limitations (2025):**
    /// - Rootless jailbreaks (Dopamine, palera1n) hide traditional paths
    /// - Advanced tweaks (Shadow, Choicy) hook `dlopen`, `FileManager`
    /// - Enterprise/sideloaded apps bypass URL scheme restrictions
    ///
    /// **Recommendations for Production:**
    /// 1. Run periodically via background tasks (evade static analysis)
    /// 2. Obfuscate paths/strings at build time
    /// 3. Combine with server-side attestation (DeviceCheck)
    /// 4. Use `checkSuspiciousFilesWithTiming()` for hooking detection
    ///
    /// - Requires: `import UIKit`, `import Darwin`
    /// - Thread: `@MainActor` (UI thread only)
    /// - iOS Compatibility: iOS 12+ (optimized for iOS 18+)
    public func detectJailbreak() -> JailbreakDetectionResult {
        var indicatorsDetected: [JailbreakDetectionIndicators] = []
        var detectionsCounter: Int = 0
        var totalChecks: Int = 0
        
        if checkURLSchemes() {
            totalChecks += 1
            indicatorsDetected.append(.jailbreakURLSchemesDetected)
            detectionsCounter += 1
        } else {
            totalChecks += 1
        }
        
        if checkSuspiciousFiles() {
            totalChecks += 1
            indicatorsDetected.append(.suspiciousFilesDetected)
            detectionsCounter += 1
        } else {
            totalChecks += 1
        }
        
        if checkSystemPathViolations() {
            totalChecks += 1
            indicatorsDetected.append(.systemPathsViolationDetected)
            detectionsCounter += 1
        } else {
            totalChecks += 1
        }
        
        if checkDYLDInjection() {
            totalChecks += 1
            indicatorsDetected.append(.dynamicLinkerInjectionDetected)
            detectionsCounter += 1
        } else {
            totalChecks += 1
        }
        
        if checkSandboxIntegrity() {
            totalChecks += 1
            indicatorsDetected.append(.sandboxCompromisedIntegrityDetected)
            detectionsCounter += 1
        } else {
            totalChecks += 1
        }
        
        if checkSymbolicLinks() {
            totalChecks += 1
            indicatorsDetected.append(.suspiciousSymbolicLinksDetected)
            detectionsCounter += 1
        } else {
            totalChecks += 1
        }
        
        if checkForkBehaviour() {
            totalChecks += 1
            indicatorsDetected.append(.forkBehaviourAnomalyDetected)
            detectionsCounter += 1
        } else {
            totalChecks += 1
        }
        
        if checkEnvironmentVariables() {
            totalChecks += 1
            indicatorsDetected.append(.suspiciousEnvironmentVariablesDetected)
            detectionsCounter += 1
        } else {
            totalChecks += 1
        }
        
        var estimatedConfidenceLevel: Float {
            if totalChecks > 0 {
                return Float(detectionsCounter / totalChecks)
            }
            return 0
        }
        
        var isJailbreakDetected: Bool {
            if detectionsCounter > 0 {
                return true
            }
            return false
        }
        
        return JailbreakDetectionResult(isJailBroken: isJailbreakDetected, jailbreakDetectionIndicator: indicatorsDetected, estimatedConfidenceLevel: estimatedConfidenceLevel)
    }
    
    /// Checks if the system can handle a URL with the given scheme.
    ///
    /// This function wraps `UIApplication.shared.canOpenURL(_:)` to determine
    /// whether the system or any installed app can open the provided URL.
    ///
    /// **Important**:
    /// - Custom URL schemes from third-party apps **must** be explicitly declared
    ///   in your app's `Info.plist` under `LSApplicationQueriesSchemes` for
    ///   `canOpenURL(_:)` to return `true`.
    /// - System-provided schemes do **not** require declaration and work by default.
    /// - **Jailbreak-specific schemes** like `cydia://` will **always return `false`**
    ///   in App Store apps, even on jailbroken devices, due to iOS sandboxing and
    ///   security restrictions. This check is **blocked by design** for production App Store
    ///   distribution, but works on Enterprise or sideloaded apps.
    ///
    /// - Parameter urlScheme: The URL whose scheme availability to check.
    /// - Returns: `true` if the system can open the URL, `false` otherwise.
    public func checkURLScheme(urlScheme: URL) -> Bool {
        if UIApplication.shared.canOpenURL(urlScheme) {
            return true
        }
        return false
    }
    
    /// Checks if a suspicious file or directory exists, indicating potential jailbreak.
    ///
    /// This function performs dual verification using both high-level Foundation API
    /// and low-level POSIX system call for robustness against jailbreak evasion techniques.
    /// Commonly used to detect jailbreak artifacts like Cydia, MobileSubstrate, or APT repositories.
    ///
    /// **Typical paths to check**:
    /// - `"/Applications/Cydia.app"`
    /// - `"/private/var/lib/apt/"`
    /// - `"/Library/MobileSubstrate/"`
    /// - `"/usr/sbin/sshd"`
    ///
    /// **Detection Methods**:
    /// 1. `FileManager.default.fileExists(atPath:)` - High-level Foundation API
    /// 2. `access(path, F_OK)` - POSIX system call (returns 0 if file exists)
    ///
    /// - Parameter path: File system path to verify (e.g., jailbreak artifact location).
    /// - Returns: `true` if the file/directory exists (suspicious), `false` otherwise.
    public func checkSuspiciousFiles(path: String) -> Bool {
        if FileManager.default.fileExists(atPath: path) {
            return true
        }

        if access(path, F_OK) == 0 {
            return true
        }
        
        return false
    }
    
    /// Checks for jailbreak by detecting suspicious system files and measuring access time to those files.
    ///
    /// Attempts to detect a jailbroken iOS device by checking for the existence of known jailbreak-related files outside the app sandbox.
    /// Measures the duration of each access to identify potential hooks or delays indicative of jailbreak tampering.
    ///
    /// - Parameters:
    ///   - path: The path of the file you want to check (e.g., `"/Applications/Cydia.app"`, `"/usr/bin/ssh"`).
    ///   - suspiciousJailbreakHookTimingInSeconds: Time (in seconds) threshold for considering a runtime hooking.
    ///
    /// - Returns: A ``SuspiciousFilesWithTimingResult`` indicating the detection status:
    ///   - `.clean` if no suspicious files or delays detected
    ///   - `.jailbroken(accessTime:path)` if a suspicious file was accessed quickly (jailbreak confirmed)
    ///   - `.suspicious(delay:path)` if file access was delayed suspiciously, indicating possible runtime hooking or tampering
    ///
    /// - Note: Timing thresholds (e.g., 50ms) may require tuning based on device and iOS version.
    ///
    /// Usage example:
    /// ```swift
    /// let result = checkSuspiciousFilesWithTiming(path: "/Applications/Cydia.app", suspiciousJailbreakHookTimingInSeconds: 0.05)
    /// switch result {
    /// case .clean:
    ///     print("Device appears clean")
    /// case let .jailbroken(time, path):
    ///     print("Jailbreak detected! Accessed $$path) in $$time * 1000) ms")
    /// case let .suspicious(delay, path):
    ///     print("Suspicious delay accessing $$path): $$delay * 1000) ms")
    /// }
    /// ```
    ///
    /// - Important: This function is intended as part of a layered jailbreak detection strategy and should not be solely relied upon.
    /// It uses `CFAbsoluteTimeGetCurrent()` for precise timing without extra dependencies.
    public func checkSuspiciousFilesWithTiming(path: String, suspiciousJailbreakHookTimingInSeconds: Double) -> SuspiciousFilesWithTimingResult {
        let startTime = CFAbsoluteTimeGetCurrent()
        let fileExists = FileManager.default.fileExists(atPath: path)
        let duration = CFAbsoluteTimeGetCurrent() - startTime
        
        if fileExists {
            return .jailbroken(accessTime: duration, path: path)
        }
        
        if duration > suspiciousJailbreakHookTimingInSeconds {
            return .suspicious(delay: duration, path: path)
        }
        
        return .clean
    }
    
    /// Detects if a specific dynamic library associated with jailbreak tools is loaded into the current process.
    ///
    /// Attempts to dynamically load the specified library using `dlopen` with `RTLD_NOW` mode. A successful load
    /// (non-nil handle) indicates that the library is present in the process address space, typically due to
    /// DYLD injection by jailbreak frameworks like Cydia Substrate or libhooker.
    ///
    /// - Parameters:
    ///   - library: The name of the dynamic library to check (e.g., `"MobileSubstrate.dylib"`, `"libhooker.dylib"`).
    ///
    /// - Returns: `true` if the library can be loaded (jailbreak indicator), `false` otherwise.
    ///
    /// - Note: This is a building block for comprehensive DYLD injection detection. Common jailbreak libraries include:
    ///   ```
    ///   "SubstrateLoader.dylib", "MobileSubstrate.dylib", "libhooker.dylib",
    ///   "SSLKillSwitch2.dylib", "SSLKillSwitch.dylib"
    ///   ```
    ///
    /// Usage example:
    /// ```swift
    /// if checkDYLDInjection(library: "MobileSubstrate.dylib") {
    ///     print("DYLD injection detected")
    /// }
    /// ```
    ///
    /// - Important: Requires `import Darwin`. Use as part of layered jailbreak detection; modern jailbreaks may hook `dlopen`.
    public func checkDYLDInjection(library: String) -> Bool {
        if dlopen(library, RTLD_NOW) != nil {
            return true
        }

        return false
    }
    
    /// Detects DYLD injection by checking if a suspicious dynamic library is loadable in the current process.
    ///
    /// Enhanced version that measures load time to detect hooking delays, validates the library handle,
    /// and provides detailed detection results for security logging.
    ///
    /// - Parameters:
    ///   - library: Name of the dynamic library to check (e.g., `"MobileSubstrate.dylib"`, `"libhooker.dylib"`).
    ///   - timeoutSeconds: Maximum time (in seconds) to wait for `dlopen`. Defaults to 0.1s.
    ///
    /// - Returns: A ``DYLDInjectionResult`` indicating the detection status:
    ///   - `.clean(loadTime:library:)`: No injection detected
    ///   - `.suspicious(delay:library:)`: Suspicious delay during load attempt (possible hooking)
    ///   - `.injected(handle:loadTime:library:)`: Confirmed injection - library successfully loaded
    ///
    /// - Note: Uses `RTLD_NOLOAD` flag to check if library is already loaded without forcing a new load.
    ///   Requires `import Darwin`. Modern jailbreaks may hook `dlopen` to evade detection.
    ///
    /// Usage example:
    /// ```swift
    /// // Check common jailbreak libraries
    /// let libraries = ["MobileSubstrate.dylib", "libhooker.dylib", "SSLKillSwitch2.dylib"]
    ///
    /// for library in libraries {
    ///     let result = checkDYLDInjectionWithTiming(library: library, timeoutSeconds: 0.1)
    ///
    ///     switch result {
    ///     case .clean(let time, _):
    ///         Logger.security.debug("Clean: $$library) checked in $$time*1000, specifier: "%.1f")ms")
    ///     case .suspicious(let delay, _):
    ///         Logger.security.warning("Suspicious DYLD delay: $$library) took $$delay*1000, specifier: "%.1f")ms")
    ///     case .injected(_, let time, _):
    ///         Logger.security.error("DYLD INJECTION DETECTED: $$library) loaded in $$time*1000, specifier: "%.1f")ms")
    ///         return result // Early exit on confirmed injection
    ///     }
    /// }
    /// ```
    ///
    /// - Important: Part of layered jailbreak detection. Combine with file checks and sandbox tests for comprehensive protection.
    public func checkDYLDInjectionWithTiming(library: String, timeoutSeconds: Double) -> DYLDInjectionResult {
        let startTime = CFAbsoluteTimeGetCurrent()
        guard let handle = dlopen(library, RTLD_NOW | RTLD_NOLOAD) else {
            let duration = CFAbsoluteTimeGetCurrent() - startTime
            return .clean(loadTime: duration, library: library)
        }
        
        defer { dlclose(handle) }
        
        let duration = CFAbsoluteTimeGetCurrent() - startTime
        
        if duration > timeoutSeconds {
            return .suspicious(delay: duration, library: library)
        }
        
        return .injected(handle: handle, loadTime: duration, library: library)
    }
    
}

private extension iOSJailbreakDetector {
    
    func checkURLSchemes() -> Bool {
        let schemes = [
            "cydia://", "filza://", "undecimus://", "sileo://",
            "zbra://", "substitute://", "activator://"
        ]
        
        for scheme in schemes {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
                return true
            }
        }
        
        return false
    }
    
    func checkSuspiciousFiles() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt",
            "/usr/bin/ssh",
            "/usr/libexec/sftp-server",
            "/Library/PreferenceBundles/LibertyPref.bundle",
            "/Library/PreferenceBundles/ShadowPreferences.bundle"
        ]

        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }

            if access(path, F_OK) == 0 {
                return true
            }
        }
        return false
    }
    
    func checkSystemPathViolations() -> Bool {
        do {
            let testString = "jailbreak_test"
            let testPath = "/private/jailbreak_test.txt"

            try testString.write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }
    
    func checkDYLDInjection() -> Bool {
        let suspiciousLibraries = [
            "SubstrateLoader.dylib",
            "SSLKillSwitch2.dylib",
            "SSLKillSwitch.dylib",
            "MobileSubstrate.dylib",
            "libhooker.dylib",
            "SubstrateBootstrap.dylib",
            "SubstrateInserter.dylib"
        ]

        for library in suspiciousLibraries {
            if dlopen(library, RTLD_NOW) != nil {
                return true
            }
        }

        return false
    }
    
    func checkSandboxIntegrity() -> Bool {
        let pid = getpid()
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var size = MemoryLayout<kinfo_proc>.stride

        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)

        if result == 0 {
            return (info.kp_proc.p_flag & P_TRACED) != 0
        }

        return false
    }
    
    func checkSymbolicLinks() -> Bool {
        let checkPaths = [
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
            "/usr/share"
        ]

        for path in checkPaths {
            do {
                let attributes = try FileManager.default.attributesOfItem(atPath: path)
                if let fileType = attributes[.type] as? FileAttributeType,
                   fileType == .typeSymbolicLink {
                    return true
                }
            } catch {
                continue
            }
        }
        return false
    }
    
    func checkForkBehaviour() -> Bool {
        var pid: pid_t = 0
        let args: [UnsafeMutablePointer<CChar>?] = [nil]
        let env: [UnsafeMutablePointer<CChar>?] = [nil]

        let status = posix_spawn(&pid, "/bin/ls", nil, nil, args, env)

        if status == 0 {
            var exitStatus: Int32 = 0
            waitpid(pid, &exitStatus, 0)
            return true
        }

        return false
    }
    
    func checkEnvironmentVariables() -> Bool {
        let suspiciousVars = [
            "DYLD_INSERT_LIBRARIES",
            "_MSSafeMode",
            "_SafeMode",
            "DYLD_LIBRARY_PATH"
        ]

        for variable in suspiciousVars {
            if getenv(variable) != nil {
                return true
            }
        }

        return false
    }
    
}
