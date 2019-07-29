//
//  PCCA_VSC.swift
//  PCCA-VSC
//  Copyright © 2019 ProofShow Inc. All rights reserved.
//

import Foundation

public class PCCA_VSC: NSObject {
    private let kKeyType = kSecAttrKeyTypeRSA
    private let kKeySize = 2048
    private var initError: Bool = false
    private var tag: String!
    
    override public init() {
        super.init()
        // generate a random string as tag name for creating key
        tag = UUID().uuidString
        var accessControlError: Unmanaged<CFError>?
        
        let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.biometryAny, .privateKeyUsage], &accessControlError)
        
        guard accessControl != nil else {
            return
        }
        // private key parameters
        let privateKeyParams: [String: AnyObject] = [
            kSecAttrIsPermanent as String: true as AnyObject,
            kSecAttrApplicationTag as String: tag as AnyObject
        ]
        
        // private key parameters
        let publicKeyParams: [String: AnyObject] = [
            kSecAttrIsPermanent as String: true as AnyObject,
            kSecAttrApplicationTag as String: tag as AnyObject
        ]
        
        // global parameters for our key generation
        let parameters: [String: AnyObject] = [
            kSecAttrKeyType as String:          kKeyType,
            kSecAttrKeySizeInBits as String:    kKeySize as AnyObject,
            kSecPublicKeyAttrs as String:       publicKeyParams as AnyObject,
            kSecPrivateKeyAttrs as String:      privateKeyParams as AnyObject,
        ]
        var pubKey, privKey: SecKey?
        let status = SecKeyGeneratePair(parameters as CFDictionary, &pubKey, &privKey)
        
        if status != errSecSuccess {
            self.initError = true
        }
    }
    
    deinit {
        // delete key
        let deleteQuery = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            ] as [String : Any]
        SecItemDelete(deleteQuery as CFDictionary)
    }
    
    /**
     Check if successfully generated key while constructing the object
     */
    open func isInitializeSuccess() -> Bool {
        return !self.initError
    }
    
    /**
     Get CSR by email address
     */
    open func getCSR(emailAddress: String) -> Data {
        let sccsr = SCCSR()
        sccsr.commonName = emailAddress
        return sccsr.build(getPublicKeyData(tag), privateKey: getPrivateKeyReference(tag))
    }
    
    /**
     Get certificate by CSR
     */
    open func getCert(csr: String, completion: @escaping (String?, Error?) -> Void) throws -> URLSessionDataTask {
        let url = URL(string: "https://proof.show/api/v1/cert")!
        let session = URLSession.init()
        let task = session.dataTask(with: url) { (data, response, error) in
            do {
                if let error = error { throw error }
                if let data = data {
                    let cert = ""
                    completion(cert, nil)
                } else {
                    completion(nil, nil)
                }
            } catch {
                completion(nil, error)
            }
        }
        task.resume()
        return task
    }
    
    /**
     Get signed hash by hash string
     */
    open func getSignedHash(hash: Data) -> Data? {
        var isSignedSuccess: Bool = true
        
        if let privateKeyRef = self.getPrivateKeyReference(tag) {
            // result data
            var resultData = Data(count: SecKeyGetBlockSize(privateKeyRef))
            let resultPointer = resultData.withUnsafeMutableBytes({ (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
                return bytes
            })
            var resultLength = resultData.count
            var hashData = hash
            let hash = hashData.withUnsafeMutableBytes({ (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
                return bytes
            })
            let status = SecKeyRawSign(privateKeyRef, SecPadding.PKCS1, hash, hashData.count, resultPointer, &resultLength)
            if status != errSecSuccess {
                isSignedSuccess = false
            }
            else {
                resultData.count = resultLength
            }
            hash.deinitialize()
            // analyze results and call the completion in main thread
            if isSignedSuccess {
                // adjust NSData length and return result.
                resultData.count = resultLength
                return resultData as Data
            } else {
                return nil
            }
        } else {
            return nil
        }
    }
    
    private func getPublicKeyData(_ tag: String) -> Data? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true
            ] as [String : Any]
        var data: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &data)
        if status == errSecSuccess {
            return data as? Data
        } else { return nil }
    }
    
    private func getPrivateKeyReference(_ tag: String) -> SecKey? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
            ] as [String : Any]
        var ref: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &ref)
        if status == errSecSuccess { return ref as! SecKey? } else { return nil }
    }
    
}

