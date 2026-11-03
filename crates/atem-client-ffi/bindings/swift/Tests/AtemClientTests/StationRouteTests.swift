import Foundation
import XCTest
import AtemClient

final class StationRouteTests: XCTestCase {
    private func vector() throws -> [String: Any] {
        let root = try XCTUnwrap(ProcessInfo.processInfo.environment["ATEM_FIXTURES"])
        let path = URL(fileURLWithPath: root).appendingPathComponent("station-route/v1.json")
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any])
    }

    private func json(_ value: Any) throws -> String {
        let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        return try XCTUnwrap(String(data: bytes, encoding: .utf8))
    }

    func testOfferAndAcceptanceMatchIndependentVectors() throws {
        let v = try vector()
        let token = try XCTUnwrap(v["test_session_token"] as? String)
        let offer = try stationRouteOffer(
            requestJson: json(XCTUnwrap(v["request"])),
            relayUrl: "https://STATION-DEV.agora.build:443/", relayOnly: true,
            sessionToken: token)
        let got = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(offer.utf8)) as? NSDictionary)
        XCTAssertEqual(got, try XCTUnwrap(v["offer"] as? NSDictionary))
        XCTAssertEqual(try stationRouteVerifyAccepted(
            offerJson: offer, acceptedJson: json(XCTUnwrap(v["accepted"])),
            sessionToken: token), 8)
    }

    func testRejectsWrongSessionAndAlteredAcceptance() throws {
        let v = try vector()
        let token = try XCTUnwrap(v["test_session_token"] as? String)
        let offer = try json(XCTUnwrap(v["offer"]))
        let accepted = try json(XCTUnwrap(v["accepted"]))
        XCTAssertThrowsError(try stationRouteVerifyAccepted(
            offerJson: offer, acceptedJson: accepted, sessionToken: "wrong-session"))
        let altered = accepted.replacingOccurrences(of: "\"direct_blocked\":true", with: "\"direct_blocked\":false")
        XCTAssertNotEqual(altered, accepted)
        XCTAssertThrowsError(try stationRouteVerifyAccepted(
            offerJson: offer, acceptedJson: altered, sessionToken: token))
        let stale = offer.replacingOccurrences(of: "station-dev.agora.build", with: "other.example")
        XCTAssertNotEqual(stale, offer)
        XCTAssertThrowsError(try stationRouteVerifyAccepted(
            offerJson: stale, acceptedJson: accepted, sessionToken: token))
    }
}
