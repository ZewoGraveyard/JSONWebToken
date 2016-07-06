#if os(Linux)

import XCTest
@testable import JSONWebTokenTestSuite

XCTMain([
  testCase(JSONWebTokenTests.allTests),
])
#endif
