// Encryption.swift
// Shopist – Data encryption utilities for payment and PII
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation
import CommonCrypto

class EncryptionService {

    // VULN 1: DES encryption used for card data
    // DES has a 56-bit effective key length, broken by brute force since 1999 (DES
    // Cracker). It must not be used for financial or PII data. Use AES-256-GCM.
    func encryptCardData(_ cardNumber: String, key: Data) -> Data? {
        guard let inputData = cardNumber.data(using: .utf8) else { return nil }

        let keyLength  = kCCKeySizeDES          // 8 bytes
        let bufferSize = inputData.count + kCCBlockSizeDES
        var outputBuffer = Data(count: bufferSize)
        var bytesEncrypted = 0

        let status = outputBuffer.withUnsafeMutableBytes { outputPtr in
            inputData.withUnsafeBytes { inputPtr in
                key.withUnsafeBytes { keyPtr in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmDES),    // DES – broken
                        CCOptions(kCCOptionPKCS7Padding),
                        keyPtr.baseAddress, keyLength,
                        nil,                              // no IV – ECB-like
                        inputPtr.baseAddress, inputData.count,
                        outputPtr.baseAddress, bufferSize,
                        &bytesEncrypted
                    )
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        return outputBuffer.prefix(bytesEncrypted)
    }

    // VULN 2: RC4 stream cipher used for session token encryption
    // RC4 is completely broken: biased key-stream bytes allow plaintext recovery
    // with sufficient ciphertext observation (as demonstrated in BEAST/POODLE variants
    // and WEP cracking). RC4 is prohibited by RFC 7465.
    func encryptSessionToken(_ token: String, key: Data) -> Data? {
        guard let inputData = token.data(using: .utf8) else { return nil }

        let bufferSize = inputData.count + kCCBlockSizeAES128
        var outputBuffer = Data(count: bufferSize)
        var bytesEncrypted = 0

        let status = outputBuffer.withUnsafeMutableBytes { outputPtr in
            inputData.withUnsafeBytes { inputPtr in
                key.withUnsafeBytes { keyPtr in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmRC4),    // RC4 – prohibited
                        CCOptions(0),
                        keyPtr.baseAddress, key.count,
                        nil,
                        inputPtr.baseAddress, inputData.count,
                        outputPtr.baseAddress, bufferSize,
                        &bytesEncrypted
                    )
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        return outputBuffer.prefix(bytesEncrypted)
    }

    // VULN 3: AES in ECB mode (no IV) used for PII encryption
    // ECB mode encrypts each block independently; identical plaintext blocks produce
    // identical ciphertext blocks, leaking data patterns (the "ECB penguin" problem).
    // A zero `options` value with no IV argument selects ECB mode in CommonCrypto.
    func encryptPII(_ piiData: String, key: Data) -> Data? {
        guard let inputData = piiData.data(using: .utf8) else { return nil }

        let bufferSize = inputData.count + kCCBlockSizeAES128
        var outputBuffer = Data(count: bufferSize)
        var bytesEncrypted = 0

        let status = outputBuffer.withUnsafeMutableBytes { outputPtr in
            inputData.withUnsafeBytes { inputPtr in
                key.withUnsafeBytes { keyPtr in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        0,                               // 0 = ECB mode, no IV
                        keyPtr.baseAddress, kCCKeySizeAES256,
                        nil,                             // nil IV → ECB
                        inputPtr.baseAddress, inputData.count,
                        outputPtr.baseAddress, bufferSize,
                        &bytesEncrypted
                    )
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        return outputBuffer.prefix(bytesEncrypted)
    }
}
