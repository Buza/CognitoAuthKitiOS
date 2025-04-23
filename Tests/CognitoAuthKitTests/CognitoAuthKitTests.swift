import Testing
@testable import CognitoAuthKitiOS

protocol CognitoTestConfigurable {
    var poolClientId: String { get }
    var poolId: String { get }
    var validUsername: String { get }
    var validPassword: String { get }
}

struct CognitoTestConfigDefault : CognitoTestConfigurable {
    let poolClientId = "<pool client id>"
    let poolId = "<pool id>"
    let validUsername = "<valid username>"
    let validPassword = "<valid password>"
}

struct AuthTests {

    let testConfig: CognitoTestConfigurable = CognitoTestConfigDefault()

    let invalidUsername = "invalid-xxx"
    let invalidPassword = "wrongPassword123"

    private func getAuth() -> Auth {
        Auth(poolClientId: testConfig.poolClientId, poolId: testConfig.poolId)
    }

    @Test func testSignIn() async throws {
        let auth = getAuth()
        let signedIn = try await auth.signIn(username: testConfig.validUsername, password: testConfig.validPassword)
        #expect(signedIn)
        let token = try await auth.getIdToken()
        #expect(!token.isEmpty)
    }

    @Test func testSignOut() async throws {
        let auth = getAuth()
        let signedIn = try await auth.signIn(username: testConfig.validUsername, password: testConfig.validPassword)
        #expect(signedIn)
        auth.signOut()
    }

    @Test func testSignInFailsWithInvalidCredentials() async throws {
        let auth = getAuth()
        do {
            _ = try await auth.signIn(username: invalidUsername, password: invalidPassword)
            preconditionFailure("Expected sign-in to fail with invalid credentials")
        } catch {
            print("Sign-in failed as expected: \(error)")
            #expect(true)
        }
    }
}
