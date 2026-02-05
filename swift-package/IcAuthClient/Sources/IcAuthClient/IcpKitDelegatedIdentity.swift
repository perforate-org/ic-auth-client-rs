import Foundation
import IcpKit

public enum AuthDelegationError: LocalizedError {
    case missingDelegationChain
    case invalidDelegationChain(String)
    case missingPublicKeyDer
    case invalidPrincipal(String)

    public var errorDescription: String? {
        switch self {
        case .missingDelegationChain:
            return "Delegation chain is missing."
        case .invalidDelegationChain(let message):
            return "Invalid delegation chain: \(message)"
        case .missingPublicKeyDer:
            return "Delegated identity public key is missing."
        case .invalidPrincipal(let value):
            return "Invalid principal: \(value)"
        }
    }
}

public final class AuthIdentitySigningPrincipal: ICPSigningPrincipal, ICPDerPublicKeyProvider {
    public let principal: ICPPrincipal
    public let rawPublicKey: Data
    public let publicKeyDer: Data

    private let identity: AuthIdentity

    public init(identity: AuthIdentity) throws {
        guard let publicKeyDer = identity.publicKeyDer() else {
            throw AuthDelegationError.missingPublicKeyDer
        }
        self.identity = identity
        self.publicKeyDer = publicKeyDer
        self.rawPublicKey = publicKeyDer
        self.principal = try ICPPrincipal(try identity.principalText())
    }

    public func sign(_ message: Data, domain: ICPDomainSeparator) async throws -> Data {
        let payload = domain.domainSeparatedData(message)
        return try identity.signArbitrary(message: payload)
    }
}

extension AuthIdentity {
    public func icpDelegatedIdentity() throws -> ICPDelegatedIdentity {
        guard let json = delegationChainJson() else {
            throw AuthDelegationError.missingDelegationChain
        }
        let parsed = try DelegationChainParser.parse(json: json)
        let signer = try AuthIdentitySigningPrincipal(identity: self)
        return ICPDelegatedIdentity.unchecked(
            fromPublicKeyDer: parsed.publicKeyDer,
            to: signer,
            chain: parsed.delegations
        )
    }
}

extension AuthClient {
    public func icpDelegatedIdentity() throws -> ICPDelegatedIdentity {
        try identity().icpDelegatedIdentity()
    }
}

private struct DelegationChainParser {
    struct ParsedChain {
        let publicKeyDer: Data
        let delegations: [ICPSignedDelegation]
    }

    static func parse(json: String) throws -> ParsedChain {
        let data = Data(json.utf8)
        let root = try JSONSerialization.jsonObject(with: data)
        guard let dict = root as? [String: Any] else {
            throw AuthDelegationError.invalidDelegationChain("Expected JSON object")
        }

        let publicKeyValue = dict["public_key"] ?? dict["publicKey"]
        guard let publicKeyValue else {
            throw AuthDelegationError.invalidDelegationChain("Missing public_key")
        }
        let publicKeyDer = try parseData(value: publicKeyValue)

        guard let delegationsValue = dict["delegations"] as? [Any] else {
            throw AuthDelegationError.invalidDelegationChain("Missing delegations")
        }

        let delegations = try delegationsValue.map { entry in
            guard let entryDict = entry as? [String: Any] else {
                throw AuthDelegationError.invalidDelegationChain("Invalid delegation entry")
            }
            return try parseSignedDelegation(entryDict)
        }

        return ParsedChain(publicKeyDer: publicKeyDer, delegations: delegations)
    }

    private static func parseSignedDelegation(_ dict: [String: Any]) throws -> ICPSignedDelegation {
        guard let delegationDict = dict["delegation"] as? [String: Any] else {
            throw AuthDelegationError.invalidDelegationChain("Missing delegation")
        }
        let delegation = try parseDelegation(delegationDict)
        guard let signatureValue = dict["signature"] else {
            throw AuthDelegationError.invalidDelegationChain("Missing signature")
        }
        let signature = try parseData(value: signatureValue)
        return ICPSignedDelegation(delegation: delegation, signature: signature)
    }

    private static func parseDelegation(_ dict: [String: Any]) throws -> ICPDelegation {
        guard let pubkeyValue = dict["pubkey"] else {
            throw AuthDelegationError.invalidDelegationChain("Missing delegation pubkey")
        }
        let pubkey = try parseData(value: pubkeyValue)
        guard let expirationValue = dict["expiration"] else {
            throw AuthDelegationError.invalidDelegationChain("Missing delegation expiration")
        }
        let expiration = try parseUInt64(value: expirationValue)
        let targets: [ICPPrincipal]?
        if let targetsValue = dict["targets"] {
            targets = try parseTargets(value: targetsValue)
        } else {
            targets = nil
        }
        return ICPDelegation(pubkey: pubkey, expiration: expiration, targets: targets)
    }

    private static func parseTargets(value: Any) throws -> [ICPPrincipal] {
        guard let list = value as? [Any] else {
            throw AuthDelegationError.invalidDelegationChain("Invalid delegation targets")
        }
        return try list.map { target in
            if let principal = try parsePrincipal(value: target) {
                return principal
            }
            throw AuthDelegationError.invalidDelegationChain("Invalid target principal")
        }
    }

    private static func parsePrincipal(value: Any) throws -> ICPPrincipal? {
        if let text = value as? String {
            if let principal = try? ICPPrincipal(text) {
                return principal
            }
            if let data = try? parseHexData(string: text) {
                return ICPPrincipal(data)
            }
            throw AuthDelegationError.invalidPrincipal(text)
        }
        if let dict = value as? [String: Any] {
            if let text = dict["string"] as? String {
                return try ICPPrincipal(text)
            }
            if let bytes = dict["bytes"] {
                let data = try parseData(value: bytes)
                return ICPPrincipal(data)
            }
        }
        if let data = try? parseData(value: value) {
            return ICPPrincipal(data)
        }
        return nil
    }

    private static func parseUInt64(value: Any) throws -> UInt64 {
        if let number = value as? NSNumber {
            return number.uint64Value
        }
        if let string = value as? String {
            if let hex = try? parseHexUInt64(string: string) {
                return hex
            }
            if let decimal = UInt64(string) {
                return decimal
            }
        }
        throw AuthDelegationError.invalidDelegationChain("Invalid expiration")
    }

    private static func parseData(value: Any) throws -> Data {
        if let data = value as? Data {
            return data
        }
        if let numbers = value as? [NSNumber] {
            return Data(numbers.map { $0.uint8Value })
        }
        if let ints = value as? [Int] {
            return Data(ints.map { UInt8($0) })
        }
        if let string = value as? String {
            if let data = try? parseHexData(string: string) {
                return data
            }
            if let data = Data(base64Encoded: string) {
                return data
            }
        }
        if let array = value as? [Any] {
            let bytes = try array.map { element -> UInt8 in
                if let number = element as? NSNumber { return number.uint8Value }
                if let int = element as? Int { return UInt8(int) }
                throw AuthDelegationError.invalidDelegationChain("Invalid byte array")
            }
            return Data(bytes)
        }
        throw AuthDelegationError.invalidDelegationChain("Invalid byte data")
    }

    private static func parseHexUInt64(string: String) throws -> UInt64 {
        let trimmed = string.lowercased().hasPrefix("0x") ? String(string.dropFirst(2)) : string
        guard let value = UInt64(trimmed, radix: 16) else {
            throw AuthDelegationError.invalidDelegationChain("Invalid hex value")
        }
        return value
    }

    private static func parseHexData(string: String) throws -> Data {
        let trimmed = string.lowercased().hasPrefix("0x") ? String(string.dropFirst(2)) : string
        var bytes = [UInt8]()
        bytes.reserveCapacity(trimmed.count / 2)
        var index = trimmed.startIndex
        while index < trimmed.endIndex {
            let next = trimmed.index(index, offsetBy: 2)
            guard next <= trimmed.endIndex else {
                throw AuthDelegationError.invalidDelegationChain("Invalid hex string length")
            }
            let byteString = trimmed[index..<next]
            guard let byte = UInt8(byteString, radix: 16) else {
                throw AuthDelegationError.invalidDelegationChain("Invalid hex string")
            }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }
}
