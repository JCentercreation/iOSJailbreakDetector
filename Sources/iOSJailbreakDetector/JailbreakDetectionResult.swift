//
//  JailbreakDetectionResult.swift
//  JailbreakDetector

public struct JailbreakDetectionResult {
    let isJailBroken: Bool
    let jailbreakDetectionIndicator: [JailbreakDetectionIndicators]
    let estimatedConfidenceLevel: Float
}
