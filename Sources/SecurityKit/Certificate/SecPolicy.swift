import Security

public extension SecPolicy {
    /// Returns a policy object for the default X.509 policy.
    static var `default`: SecPolicy {
        SecPolicyCreateBasicX509()
    }
}
