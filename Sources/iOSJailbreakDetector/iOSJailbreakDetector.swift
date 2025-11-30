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
