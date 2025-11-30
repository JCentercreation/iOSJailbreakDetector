//
//  JailbreakDetectionIndicators.swift
//  JailbreakDetector

public enum JailbreakDetectionIndicators: CaseIterable {
    case jailbreakURLSchemesDetected
    case suspiciusFilesDetected
    case systemPathsViolatedDetected
    case dynamicLinkerInjectionDetected
    case sandboxCompromisedIntegrityDetected
    case suspiciousSymbolicLinksDetected
    case forkBehaviourAnomalyDetected
    case suspiciousEnvironmentVariablesDetected
}
