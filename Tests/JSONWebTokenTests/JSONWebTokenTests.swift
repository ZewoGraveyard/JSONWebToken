import XCTest
@testable import JSONWebToken

class JSONWebTokenTests: XCTestCase {
    func testReality() {
        XCTAssert(2 + 2 == 4, "Something is severely wrong here.")
    }
}

extension JSONWebTokenTests {
    static var allTests: [(String, (JSONWebTokenTests) -> () throws -> Void)] {
        return [
           ("testReality", testReality),
        ]
    }
}
