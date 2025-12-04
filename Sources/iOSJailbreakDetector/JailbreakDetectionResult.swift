//
//  JailbreakDetectionResult.swift
//  iOSJailbreakDetector

/// Comprehensive result structure containing all jailbreak detection outcomes.
///
/// Aggregates results from multiple detection vectors into a single response with confidence scoring.
/// Designed for security logging, risk assessment, and conditional app behavior.
///
/// **Usage Example:**
/// ```swift
/// let result = iOSJailbreakDetector.shared.detectJailbreak()
/// if result.isJailBroken && result.estimatedConfidenceLevel > 0.5 {
///     // High-confidence jailbreak - restrict sensitive features
///     showJailbreakWarning()
/// }
/// Logger.security.info("Jailbreak indicators: $$result.jailbreakDetectionIndicator)")
/// ```
///
/// - Parameters:
///   - isJailBroken: `true` if any detection indicators were triggered
///   - jailbreakDetectionIndicator: Array of specific indicators that fired (for forensics)
///   - estimatedConfidenceLevel: Detection confidence (0.0 = clean, 1.0 = all checks failed)
public struct JailbreakDetectionResult {
    public let isJailBroken: Bool
    public let jailbreakDetectionIndicator: [JailbreakDetectionIndicators]
    public let estimatedConfidenceLevel: Float
}
