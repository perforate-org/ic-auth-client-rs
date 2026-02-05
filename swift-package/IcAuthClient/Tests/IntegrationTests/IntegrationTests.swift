import Foundation
import IcAuthClient
import IcpKit
import XCTest

final class IcAuthIntegrationTests: XCTestCase {
    private struct SigningPrincipal: ICPSigningPrincipal {
        let principal: ICPPrincipal
        let rawPublicKey: Data
        let privateKey: Data

        func sign(_ message: Data, domain: ICPDomainSeparator) async throws -> Data {
            try ICPCryptography.ellipticSign(message, domain: domain, with: privateKey)
        }
    }

    func testKeyMaterialAndPrincipalInterop() async throws {
        let serviceName = "ic-auth-client-integration"
        let existing = try AuthClient(serviceName: serviceName)
        existing.logout()

        let client = try AuthClient(serviceName: serviceName)
        defer { client.logout() }
        XCTAssertEqual(client.baseKeyType(), "Secp256k1")
        let principalText = try client.principalText()
        XCTAssertNotEqual(principalText, "2vxsx-fae")

        let publicKey = try client.secp256k1UncompressedPublicKey()
        let privateKey = try client.secp256k1PrivateKey()

        XCTAssertEqual(publicKey.count, 65)
        XCTAssertEqual(privateKey.count, 32)

        let principal = try ICPPrincipal(principalText)
        let signingPrincipal = SigningPrincipal(
            principal: principal,
            rawPublicKey: publicKey,
            privateKey: privateKey
        )

        let signature = try await signingPrincipal.sign(
            Data([0x01, 0x02, 0x03]), domain: "ic-request")
        XCTAssertEqual(signature.count, 65)
    }
}
