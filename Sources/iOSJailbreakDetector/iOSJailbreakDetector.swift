// The Swift Programming Language
// https://docs.swift.org/swift-book

import UIKit

@MainActor
public final class iOSJailbreakDetector {
    
    public static let shared = iOSJailbreakDetector()
    
    private init() { }
    
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
    /// - Returns: A `SuspiciousFilesWithTimingResult` indicating the detection status:
    ///   - `.clean` if no suspicious files or delays detected
    ///   - `.jailbroken(accessTime:path)` if a suspicious file was accessed quickly (jailbreak confirmed)
    ///   - `.suspicious(delay:path)` if file access was delayed suspiciously, indicating possible runtime hooking or tampering
    ///
    /// - Note: Timing thresholds (e.g., 50ms) may require tuning based on device and iOS version.
    ///
    /// Usage example:
    /// ```
    /// let result = checkSuspiciousFilesWithTiming(path: "/Applications/Cydia.app", suspiciousJailbreakHookTimingInMiliSeconds: 0.05)
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
    public func checkSuspiciousFilesWithTiming(path: String, suspiciousJailbreakHookTimingInMiliSeconds: Double) -> SuspiciousFilesWithTimingResult {
        let startTime = CFAbsoluteTimeGetCurrent()
        let fileExists = FileManager.default.fileExists(atPath: path)
        let duration = CFAbsoluteTimeGetCurrent() - startTime
        
        if fileExists {
            return .jailbroken(accessTime: duration, path: path)
        }
        
        if duration > suspiciousJailbreakHookTimingInMiliSeconds {
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
    /// ```
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
    
}

extension iOSJailbreakDetector {
    
    private func checkURLSchemes() -> Bool {
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
    
    private func checkSuspiciousFiles() -> Bool {
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
    
    private func checkSystemPathViolations() -> Bool {
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
    
    private func checkDYLDInjection() -> Bool {
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
    
}
