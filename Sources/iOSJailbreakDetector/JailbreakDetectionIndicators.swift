//
//  File.swift
//  iOSJailbreakDetector

/// Individual jailbreak detection indicators for granular reporting.
///
/// Each case represents a specific detection vector. `CaseIterable` enables:
/// - Iteration over all possible indicators
/// - Bitmask-style tracking
/// - Logging and analytics
///
/// **Usage Examples:**
/// ```swift
/// // Iterate all possible indicators
/// for indicator in JailbreakDetectionIndicators.allCases {
///     print(indicator.rawValue)
/// }
///
/// // Check specific indicator
/// if result.jailbreakDetectionIndicator.contains(.dynamicLinkerInjectionDetected) {
///     reportDYLDInjection()
/// }
/// ```
public enum JailbreakDetectionIndicators: CaseIterable {
    case jailbreakURLSchemesDetected
    case suspiciousFilesDetected
    case systemPathsViolationDetected
    case dynamicLinkerInjectionDetected
    case sandboxCompromisedIntegrityDetected
    case suspiciousSymbolicLinksDetected
    case forkBehaviourAnomalyDetected
    case suspiciousEnvironmentVariablesDetected
}
