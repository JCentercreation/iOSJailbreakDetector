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
    
}
