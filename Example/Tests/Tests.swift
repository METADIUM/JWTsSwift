import XCTest
import JWTsSwift
import CommonCrypto
import secp256k1_swift

class Tests: XCTestCase {
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func sha256(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(data.count), &hash)
        }
        return Data(bytes: hash)
    }
    
    func hexString(data: Data) -> String {
        return data.map{ String(format:"%02x", $0) }.joined();
    }
    
    func hexadecimal(hexString: String) -> Data? {
        var data = Data(capacity: hexString.count / 2)
        
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: hexString, options: [], range: NSMakeRange(0, hexString.count)) { match, flags, stop in
            let byteString = (hexString as NSString).substring(with: match!.range)
            var num = UInt8(byteString, radix: 16)!
            data.append(&num, count: 1)
        }
        
        guard data.count > 0 else {
            return nil
        }
        
        return data
    }
    // Test secp256k1 sign / verify
    func testSignAndVerify() {
        // hash to sign
        guard let message = "test message".data(using: .utf8) else {
            XCTAssert(false)
            return;
        }
        let hash = sha256(data: message)
        
        // generate secp256k1 keypair
        guard let privateKey = SECP256K1.generatePrivateKey() else { return XCTAssert(false) };
        guard let publicKey = SECP256K1.privateToPublic(privateKey: privateKey) else { return XCTAssert(false) }
        print("private key = "+hexString(data: privateKey))
        print("public key = "+hexString(data: publicKey))
        
        // ecdsa signing with private key
        guard case let (serializedSignature?, rawSignature?) = SECP256K1.ecdsaSign(hash: hash, privateKey: privateKey) else {
            return XCTAssert(false)
        };
        // serializedSignature : compressed format R+S
        // rawSignature : low form signature
        print("serializedSignature = "+hexString(data: serializedSignature))
        print("rawSignature = "+hexString(data: rawSignature))
        
        // serializedSignature verify with public key
        let verify = SECP256K1.ecdsaVerify(hash: hash, signature: serializedSignature, publicKey: publicKey)
        XCTAssert(verify)
    }
    
    // Test JWSHeader
    func testJWSHeader() {
        let header = JWSHeader.init(algorithm: SignatureAlgorithm.ES256K)
        header.kid = "did:meta:00000054#ManagementKey#848594325849485"
        
        XCTAssertEqual("ES256K", header.parameters["alg"] as! String)
        XCTAssertEqual("did:meta:00000054#ManagementKey#848594325849485", header.kid)
        
        guard let headerBase64 = header.base64() else {
            XCTAssert(false)
            return
        }
        print("header base64 "+headerBase64)
        
        guard let resultHeader = try? JWSHeader.init(headerData: header.data()!) else {
            XCTAssert(false)
            return
        }
        XCTAssertEqual("ES256K", resultHeader.parameters["alg"] as! String)
        XCTAssertEqual("did:meta:00000054#ManagementKey#848594325849485", resultHeader.kid)
    }
    
    // Test JWS sign / verify
    func testJwsSign() {
        // Generate secp256k1 keypair
        guard let privateKey = SECP256K1.generatePrivateKey() else { return XCTAssert(false) };
        guard let publicKey = SECP256K1.privateToPublic(privateKey: privateKey) else { return XCTAssert(false) }
        print("publickey = "+hexString(data: publicKey))
        
        // set header. kid
        let header = JWSHeader.init(algorithm: SignatureAlgorithm.ES256K)
        header.kid = "did:meta:00000054#ManagementKey#848594325849485"
        
        // Make JWS
        let jwsObject = JWSObject.init(header: header, payload: "abc".data(using: .utf8)!)
        XCTAssertNotNil(jwsObject.header)
        XCTAssertNotNil(jwsObject.payload)
        
        // Init signer to sign JWS
        let signer = ECDSASigner.init(privateKey: privateKey)
        do {
            // sign
            try jwsObject.sign(signer: signer);
            
            // serialize JWS. base64(header).base64(payload).base64(signature)
            let jwsToken = try jwsObject.serialize()
            print("JWS : "+jwsToken)
            
            // Load serialized JWS
            let outputJws = try JWSObject.init(string: jwsToken)
            XCTAssertEqual(jwsObject.header.kid, outputJws.header.kid)
            XCTAssertEqual(jwsObject.header.alg, outputJws.header.alg)
            XCTAssertEqual(jwsObject.payload, jwsObject.payload)
            XCTAssertEqual(jwsObject.signature, jwsObject.signature)
            
            // Verify JWS
            let verified = try outputJws.verify(verifier: ECDSAVerifier.init(publicKey: publicKey))
            XCTAssertTrue(verified)
        }
        catch {
            XCTAssert(false)
            print("ERROR : \(error)")
        }
    }
    
    func makeJWT() -> JWT {
        let nbf = Date.init(timeIntervalSince1970: 1565941504)
        let iat = Date.init(timeIntervalSince1970: 1565941504)
        let exp = Date.init(timeIntervalSince1970: 1568533504)
        
        // Make JWT
        let jwt = JWT.init()
        jwt.issuer = URL.init(string: "did:meta:00000054")
        jwt.subject = "did:meta:00000348385"
        jwt.setAudience(audience: "did:meta:11111111")
        jwt.expirationTime = exp
        jwt.notBeforeTime = nbf
        jwt.issuedAt = iat
        jwt.jwtID = "http://aaa.com/djkd"
        
        XCTAssertEqual(jwt.issuer?.absoluteString, "did:meta:00000054")
        XCTAssertEqual(jwt.subject, "did:meta:00000348385")
        XCTAssertTrue(jwt.audience?.count == 1)
        XCTAssertEqual(jwt.audience?[0], "did:meta:11111111")
        XCTAssertEqual(jwt.expirationTime, exp)
        XCTAssertEqual(jwt.issuedAt, iat)
        XCTAssertEqual(jwt.notBeforeTime, nbf)
        XCTAssertEqual(jwt.jwtID, "http://aaa.com/djkd")
        
        do {
            // Serializing JWT
            let serializedJwt = try jwt.base64()
            print("JWT : "+serializedJwt)
            
            // Deserializing JWT
            let outpuJwt = try JWT.init(base64EncodedJson: serializedJwt)
            
            XCTAssertEqual(jwt.issuer, outpuJwt.issuer)
            XCTAssertEqual(jwt.subject, outpuJwt.subject)
            XCTAssertEqual(jwt.audience, outpuJwt.audience)
            XCTAssertEqual(jwt.expirationTime, outpuJwt.expirationTime)
            XCTAssertEqual(jwt.issuedAt, outpuJwt.issuedAt)
            XCTAssertEqual(jwt.notBeforeTime, outpuJwt.notBeforeTime)
            XCTAssertEqual(jwt.jwtID, outpuJwt.jwtID)
        }
        catch {
            XCTAssert(false)
        }
        return jwt
    }
    
    // Test JWT
    func testJWT() {
        _ = makeJWT()
    }
    
    // Test signed jwt (JWTs)
    func testSignedJWT() {
        // Make JWT
        let jwt = makeJWT()
        var serializedJWT: String
        do {
            serializedJWT = try jwt.base64()
        }
        catch {
            XCTAssert(false)
            return
        }
        
        // Generate secp256k1 keypair
        guard let privateKey = SECP256K1.generatePrivateKey() else { return XCTAssert(false) };
        guard let publicKey = SECP256K1.privateToPublic(privateKey: privateKey) else { return XCTAssert(false) }
        print("publickey = "+hexString(data: publicKey))
        
        // Make JWS
        let header = JWSHeader.init(algorithm: SignatureAlgorithm.ES256K)
        header.kid = "did:meta:00000054#ManagementKey#848594325849485"
        let jwsObject = JWSObject.init(header: header, payload: serializedJWT.data(using: .utf8)!)
        
        // Init signer to sign JWS
        let signer = ECDSASigner.init(privateKey: privateKey)
        do {
            // sign
            try jwsObject.sign(signer: signer);
            
            // serialize JWS. base64(header).base64(payload).base64(signature)
            let serializedJWS = try jwsObject.serialize()
            print("JWS : "+serializedJWS)
            
            // Load serialized JWS
            let outputJws = try JWSObject.init(string: serializedJWS)
            
            // Verify JWS
            let verified = try outputJws.verify(verifier: ECDSAVerifier.init(publicKey: publicKey))
            XCTAssertTrue(verified)
            
            let payloadString = String(data: outputJws.payload, encoding: .utf8)
            
            XCTAssertEqual(serializedJWT, payloadString)
            
            // Deserialize JWT
            let _ = try JWT.init(base64EncodedJson: payloadString!)
        }
        catch {
            XCTAssert(false)
            print("ERROR : \(error)")
        }
    }
    
}
