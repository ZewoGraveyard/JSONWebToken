// JSONWebToken.swift
//
// The MIT License (MIT)
//
// Copyright (c) 2016 Zewo
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDINbG BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import Foundation
import Core
import OpenSSL

internal extension Data {
	internal init?(urlSafeBase64Encoded base64String: String) {
		let len = base64String.characters.count
		let paddedLength = len + (4 - (len % 4))
		let correctBase64String = base64String.padding(toLength: paddedLength, withPad: "=", startingAt: 0)
		self.init(base64Encoded: correctBase64String)
	}
	
	internal func urlSafeBase64EncodedString() -> String {
		var str = base64EncodedString()
		str = str.replacingOccurrences(of: "/", with: "_")
		str = str.replacingOccurrences(of: "+", with: "-")
		str = str.replacingOccurrences(of: "=", with: "")
		return str
	}
}

public struct JSONWebToken {
	
	public enum JWTError: Error {
		case missingComponents
		case invalidSignature
		case invalidExpiration
		case invalidPayload
		case expired
	}
	
	public enum Algorithm {
		case hs256(key: Data)
		case hs384(key: Data)
		case hs512(key: Data)
		
		case rs256(key: Key)
		case rs384(key: Key)
		case rs512(key: Key)
		
		var string: String {
			switch self {
			case .hs256:
				return "HS256"
			case .hs384:
				return "HS384"
			case .hs512:
				return "HS512"
			case .rs256:
				return "RS256"
			case .rs384:
				return "RS384"
			case .rs512:
				return "RS512"
			}
		}
		
		func encode(data: Data) throws -> Data {
			switch self {
			case .hs256(let key):
				return Hash.hmac(.sha256, key: key, message: data)
			case .hs384(let key):
				return Hash.hmac(.sha384, key: key, message: data)
			case .hs512(let key):
				return Hash.hmac(.sha512, key: key, message: data)
			case .rs256(let key):
				return try Hash.rsa(.sha256, key: key, message: data)
			case .rs384(let key):
				return try Hash.rsa(.sha384, key: key, message: data)
			case .rs512(let key):
				return try Hash.rsa(.sha512, key: key, message: data)
			}
		}
	}
	
	public struct Payload: MapRepresentable, MapConvertible {
		
		public var map: Map = [:]
		
		public var iss: String? {
			get { return try? map.get("iss") }
			set { if let newValue = newValue { _ = try? map.set(newValue, for: "iss") } else { _ = try? map.remove("iss") } }
		}
		
		public var sub: String? {
			get { return try? map.get("sub") }
			set { if let newValue = newValue { _ = try? map.set(newValue, for: "sub") } else { _ = try? map.remove("sub") } }
		}
		
		public var iat: Int? {
			get { return try? map.get("iat") }
			set { if let newValue = newValue { _ = try? map.set(newValue, for: "iat") } else { _ = try? map.remove("iat") } }
		}
		
		public var exp: Int? {
			get { return try? map.get("exp") }
			set { if let newValue = newValue { _ = try? map.set(newValue, for: "exp") } else { _ = try? map.remove("exp") } }
		}
		
		public init() {}
		
		public init(map: Map) throws {
			self.map = map
		}
		
		public mutating func expire(after: Int) {
			let timestamp = time(nil)
			self.iat = timestamp
			self.exp = timestamp + after
		}
		
	}
	
	private static let jsonParser = JSONMapParser()
	private static let jsonSerializer = JSONMapSerializer()
	
	public static func encode(payload: Payload, algorithm: Algorithm? = nil) throws -> String {
		let header: Map = [
			"alg": try (algorithm?.string ?? "none").asMap(),
			"typ": "JWT"
		]
		
		let headerBase64 = try jsonSerializer.serialize(header).urlSafeBase64EncodedString()
		let payloadBase64 = try jsonSerializer.serialize(payload.map).urlSafeBase64EncodedString()
		
		let message = headerBase64 + "." + payloadBase64
		
		guard let algorithm = algorithm else { return message }
		
		let encoded = try algorithm.encode(data: message.data)
		let signature = encoded.urlSafeBase64EncodedString()
		return message + "." + signature
	}
	
	public static func decode(string: String, algorithms: [Algorithm] = []) throws -> Payload {
		let comps = string.split(separator: ".")
		guard comps.count == 3 else { throw JWTError.missingComponents }
		
		let headerBase64 = comps[0]
		let payloadBase64 = comps[1]
		var signature = comps[2]
		
		signature = signature.replacingOccurrences(of: "+", with: "-")
		signature = signature.replacingOccurrences(of: "/", with: "_")
		signature = signature.replacingOccurrences(of: "=", with: "")
		
		let message = (headerBase64 + "." + payloadBase64).data
		
		var valid = algorithms.count == 0
		for algorithm in algorithms {
			if try algorithm.encode(data: message).urlSafeBase64EncodedString() == signature {
				valid = true
				break
			}
		}
		
		guard valid else {
			throw JWTError.invalidSignature
		}
		
		guard let payloadJson = Data(urlSafeBase64Encoded: payloadBase64) else {
			throw JWTError.invalidPayload
		}
		
		let payload = try jsonParser.parse(payloadJson)
		
		let expVal = payload["exp"]
		let exp: Int
		switch expVal {
		case .string(let expStr):
			guard let expInt = Int(expStr) else {
				throw JWTError.invalidExpiration
			}
			exp = expInt
		case .int(let expInt):
			exp = expInt
		case .double(let expDouble):
			exp = Int(expDouble)
		default:
			throw JWTError.invalidExpiration
		}
		
		if exp < time(nil) {
			throw JWTError.expired
		}
		
		return try Payload(map: payload)
	}
	
	public static func decode(string: String, algorithm: Algorithm? = nil) throws -> Payload {
		var algorithms: [Algorithm] = []
		if let algorithm = algorithm { algorithms.append(algorithm) }
		return try decode(string: string, algorithms: algorithms)
	}
	
}
