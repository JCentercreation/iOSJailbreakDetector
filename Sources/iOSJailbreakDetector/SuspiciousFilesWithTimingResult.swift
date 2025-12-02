//
//  File.swift
//  SuspiciousFilesWithTimingResult

public enum SuspiciousFilesWithTimingResult {
    case clean
    case jailbroken(accessTime: Double, path: String)
    case suspicious(delay: Double, path: String)
}
