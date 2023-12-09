import SwiftRs
import CryptoKit
import LocalAuthentication

// reference:
// https://zenn.dev/iceman/scraps/380f69137c7ea2
// https://www.andyibanez.com/posts/cryptokit-secure-enclave/
@_cdecl("is_support_secure_enclave")
func isSupportSecureEnclave() -> Bool {
    return SecureEnclave.isAvailable
}

@_cdecl("generate_secure_enclave_p256_keypair")
func generateSecureEnclaveP256KeyPair() -> SRString {
    var error: Unmanaged<CFError>? = nil;
    guard let accessCtrl = SecAccessControlCreateWithFlags(
       nil,
       kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
       [.privateKeyUsage, .biometryCurrentSet],
       &error
    ) else {
        return SRString("err:\(error.debugDescription)")
    }
    do {
        let privateKeyReference = try SecureEnclave.P256.KeyAgreement.PrivateKey.init(
           accessControl: accessCtrl
        );
        let publicKeyBase64 = privateKeyReference.publicKey.x963Representation.base64EncodedString()
        let dataRepresentationBase64 = privateKeyReference.dataRepresentation.base64EncodedString()
        return SRString("ok:\(publicKeyBase64),\(dataRepresentationBase64)")
    } catch {
        return SRString("err:\(error)")
    }
}

@_cdecl("compute_secure_enclave_p256_ecdh")
func computeSecureEnclaveP256Ecdh(privateKeyDataRepresentation: SRString, ephemeraPublicKey: SRString) -> SRString {
    guard let privateKeyDataRepresentation = Data(
        base64Encoded: privateKeyDataRepresentation.toString()
    ) else {
       return SRString("err:private key base64 decode failed")
    }
    guard let ephemeralPublicKeyRepresentation = Data(
        base64Encoded: ephemeraPublicKey.toString()
    ) else {
       return SRString("err:ephemeral public key base64 decode failed")
    }
    do {
        let context = LAContext();
        let p =  try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: privateKeyDataRepresentation,
            authenticationContext: context
        )

        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey.init(derRepresentation: ephemeralPublicKeyRepresentation)

        let sharedSecret = try p.sharedSecretFromKeyAgreement(
            with: ephemeralPublicKey)

        return SRString("ok:\(sharedSecret.description)")
    } catch {
        return SRString("err:\(error)")
    }
}
