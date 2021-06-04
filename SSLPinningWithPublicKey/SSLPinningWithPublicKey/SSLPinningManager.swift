//
//  SSLPinningManager.swift
//  SSLPinningWithPublicKey
//
//  Created by madhavi.yalamaddi on 05/06/21.
//

import Foundation
import Security
import CommonCrypto

class SSLPinningManager: NSObject, URLSessionDelegate {
    static let shared = SSLPinningManager()
    
    var hardcodedPublicKey:String = "iie1VXtL7HzAMF+/PVPR9xzT80kQxdZeJ+zduCB3uj0="
    
    let rsa2048Asn1Header:[UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]
    
    private func sha256(data : Data) -> String {
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        keyWithHeader.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(keyWithHeader.count), &hash)
        }
        return Data(hash).base64EncodedString()
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        if let certificate = SecTrustGetCertificateAtIndex(serverTrust, 2) {
            let serverPublicKey = SecCertificateCopyKey(certificate)
            let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil)
            let serverHashKey = sha256(data: serverPublicKeyData as! Data)
            if serverHashKey == hardcodedPublicKey {
                print("PublicKey matched")
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
            } else {
                print("PublicKey not matched")
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    func callRemoteService(urlString: String, response: @escaping((String) -> ())) {
        let sessionObject = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        
        guard let url = URL(string: urlString) else {
            fatalError("Wrong URL entered")
        }
        
        let task = sessionObject.dataTask(with: url) { (data, result, error) in
            if error?.localizedDescription == "canclled" {
                response("ssl pinning failed")
            }
            
            if let dataReceived = data {
                let decodedString = String(decoding: dataReceived, as: UTF8.self)
                response("SSLPinning successful with public key")
                //print(decodedString)
            } else {
                response("SSLPinning failed")
            }
        }
        task.resume()
    }
}
