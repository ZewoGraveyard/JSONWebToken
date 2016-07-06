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

@_exported import POSIX
@_exported import JSON
@_exported import Base64
@_exported import OpenSSL

public struct JSONWebToken {
	
	public enum Error: ErrorProtocol {
		case MissingComponents
		case InvalidSignature
		case InvalidExpiration
		case Expired
	}
	
	public enum Algorithm {
		case HS256(key: Data)
		case HS384(key: Data)
		case HS512(key: Data)
		
		case RS256(key: Key)
		case RS384(key: Key)
		case RS512(key: Key)
		
		var string: String {
			switch self {
			case .HS256:
				return "HS256"
			case .HS384:
				return "HS384"
			case .HS512:
				return "HS512"
			case .RS256:
				return "RS256"
			case .RS384:
				return "RS384"
			case .RS512:
				return "RS512"
			}
		}
		
		func encode(data: Data) throws -> Data {
			switch self {
			case .HS256(let key):
				return Hash.hmac(.SHA256, key: key, message: data)
			case .HS384(let key):
				return Hash.hmac(.SHA384, key: key, message: data)
			case .HS512(let key):
				return Hash.hmac(.SHA512, key: key, message: data)
			case .RS256(let key):
				return try Hash.rsa(.SHA256, key: key, message: data)
			case .RS384(let key):
				return try Hash.rsa(.SHA384, key: key, message: data)
			case .RS512(let key):
				return try Hash.rsa(.SHA512, key: key, message: data)
			}
		}
	}
	
	private static let jsonParser: JSONStructuredDataParser! = JSONStructuredDataParser()
	private static let jsonSerializer: JSONStructuredDataSerializer! = JSONStructuredDataSerializer()
	
	public static func encode(payload: StructuredData, algorithm: Algorithm? = nil) throws -> String {
		let header: StructuredData = .infer([
			"alg": .infer(algorithm?.string ?? "none"),
			"typ": "JWT"
		])
		
		let headerBase64 = try Base64.encode(JSONWebToken.jsonSerializer.serialize(header), specialChars: "-_", paddingChar: nil)
		let payloadBase64 = try Base64.encode(JSONWebToken.jsonSerializer.serialize(payload), specialChars: "-_", paddingChar: nil)
		
		let message = headerBase64 + "." + payloadBase64
		
		guard let algorithm = algorithm else { return message }
		
		let encoded = try algorithm.encode(data: message.data)
		let signature = Base64.encode(encoded, specialChars: "-_", paddingChar: nil)
		return message + "." + signature
	}
	
	public static func decode(string: String, algorithms: [Algorithm] = []) throws -> StructuredData {
		let comps = string.split(separator: ".")
		guard comps.count == 3 else { throw Error.MissingComponents }
		
		let headerBase64 = comps[0]
		let payloadBase64 = comps[1]
		var signature = comps[2]
		
		signature.replace(string: "+", with: "-")
		signature.replace(string: "/", with: "_")
		signature.replace(string: "=", with: "")
		
		let message = (headerBase64 + "." + payloadBase64).data
		
		var valid = algorithms.count == 0
		for algorithm in algorithms {
			if try Base64.urlSafeEncode(algorithm.encode(data: message)) == signature {
				valid = true
				break
			}
		}
		
		guard valid else {
			throw Error.InvalidSignature
		}
		
		let payloadJson = try Base64.decode(payloadBase64)
		let payload = try JSONWebToken.jsonParser.parse(payloadJson)
		
		if let expVal = payload["exp"] {
			let exp: Int
			
			if let expInt = expVal.intValue {
				exp = expInt
			} else if let expDouble = expVal.doubleValue {
				exp = Int(expDouble)
			} else if let expStr = expVal.stringValue, expInt = Int(expStr) {
				exp = expInt
			} else {
				throw Error.InvalidExpiration
			}
			
			if exp < time(nil) {
				throw Error.Expired
			}
		}
		
		return payload
	}
	
	public static func decode(string: String, algorithm: Algorithm? = nil) throws -> StructuredData {
		var algorithms: [Algorithm] = []
		if let algorithm = algorithm { algorithms.append(algorithm) }
		return try decode(string: string, algorithms: algorithms)
	}
	
}
