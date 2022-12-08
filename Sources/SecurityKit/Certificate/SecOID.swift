/// ASN.1 Object Identifiers for X.509 and X.520 attributes.
public enum SecOID: String {
    // X.520 DN component
    case objectClass = "2.5.4.0"

    // X.520 DN component
    case aliasedEntryName = "2.5.4.1"

    // X.520 DN component
    case knowledgeInformation = "2.5.4.2"

    // X.520 DN component
    case commonName = "2.5.4.3"

    // X.520 DN component
    case surname = "2.5.4.4"

    // X.520 DN component
    case serialNumber = "2.5.4.5"

    // X.520 DN component
    case countryName = "2.5.4.6"

    // X.520 DN component
    case localityName = "2.5.4.7"

    // X.520 DN component
    case collectiveLocalityName = "2.5.4.7.1"

    // X.520 DN component
    case stateOrProvinceName = "2.5.4.8"

    // X.520 DN component
    case collectiveStateOrProvinceName = "2.5.4.8.1"

    // X.520 DN component
    case streetAddress = "2.5.4.9"

    // X.520 DN component
    case collectiveStreetAddress = "2.5.4.9.1"

    // X.520 DN component
    case organizationName = "2.5.4.10"

    // X.520 DN component
    case collectiveOrganizationName = "2.5.4.10.1"

    // X.520 DN component
    case organizationalUnitName = "2.5.4.11"

    // X.520 DN component
    case collectiveOrganizationalUnitName = "2.5.4.11.1"

    // X.520 DN component
    case title = "2.5.4.12"

    // X.520 DN component
    case description = "2.5.4.13"

    // X.520 DN component
    case searchGuide = "2.5.4.14"

    // X.520 DN component
    case businessCategory = "2.5.4.15"

    // X.520 DN component
    case postalAddress = "2.5.4.16"

    // X.520 DN component
    case collectivePostalAddress = "2.5.4.16.1"

    // X.520 DN component
    case postalCode = "2.5.4.17"

    // X.520 DN component
    case collectivePostalCode = "2.5.4.17.1"

    // X.520 DN component
    case postOfficeBox = "2.5.4.18"

    // X.520 DN component
    case collectivePostOfficeBox = "2.5.4.18.1"

    // X.520 DN component
    case physicalDeliveryOfficeName = "2.5.4.19"

    // X.520 DN component
    case collectivePhysicalDeliveryOfficeName = "2.5.4.19.1"

    // X.520 DN component
    case telephoneNumber = "2.5.4.20"

    // X.520 DN component
    case collectiveTelephoneNumber = "2.5.4.20.1"

    // X.520 DN component
    case telexNumber = "2.5.4.21"

    // X.520 DN component
    case collectiveTelexNumber = "2.5.4.21.1"

    // X.520 DN component
    case teletexTerminalIdentifier = "2.5.4.22"

    // X.520 DN component
    case collectiveTeletexTerminalIdentifier = "2.5.4.22.1"

    // X.520 DN component
    case facsimileTelephoneNumber = "2.5.4.23"

    // X.520 DN component
    case collectiveFacsimileTelephoneNumber = "2.5.4.23.1"

    // X.520 DN component
    case x121Address = "2.5.4.24"

    // X.520 DN component
    case internationalISDNNumber = "2.5.4.25"

    // X.520 DN component
    case collectiveInternationalISDNNumber = "2.5.4.25.1"

    // X.520 DN component
    case registeredAddress = "2.5.4.26"

    // X.520 DN component
    case destinationIndicator = "2.5.4.27"

    // X.520 DN component
    case preferredDeliveryMehtod = "2.5.4.28"

    // X.520 DN component
    case presentationAddress = "2.5.4.29"

    // X.520 DN component
    case supportedApplicationContext = "2.5.4.30"

    // X.520 DN component
    case member = "2.5.4.31"

    // X.520 DN component
    case owner = "2.5.4.32"

    // X.520 DN component
    case roleOccupant = "2.5.4.33"

    // X.520 DN component
    case seeAlso = "2.5.4.34"

    // X.520 DN component
    case userPassword = "2.5.4.35"

    // X.520 DN component
    case userCertificate = "2.5.4.36"

    // X.520 DN component
    case caCertificate = "2.5.4.37"

    // X.520 DN component
    case authorityRevocationList = "2.5.4.38"

    // X.520 DN component
    case certificateRevocationList = "2.5.4.39"

    // X.520 DN component
    case crossCertificatePair = "2.5.4.40"

    // X.520 DN component
    case name = "2.5.4.41"

    // X.520 DN component
    case givenName = "2.5.4.42"

    // X.520 DN component
    case initials = "2.5.4.43"

    // X.520 DN component
    case generationQualifier = "2.5.4.44"

    // X.520 DN component
    case uniqueIdentifier = "2.5.4.45"

    // X.520 DN component
    case dnQualifier = "2.5.4.46"

    // X.520 DN component
    case enhancedSearchGuide = "2.5.4.47"

    // X.520 DN component
    case protocolInformation = "2.5.4.48"

    // X.520 DN component
    case distinguishedName = "2.5.4.49"

    // X.520 DN component
    case uniqueMember = "2.5.4.50"

    // X.520 DN component
    case houseIdentifier = "2.5.4.51"

    // X.520 DN component
    case supportedAlgorithms = "2.5.4.52"

    // X.520 DN component
    case deltaRevocationList = "2.5.4.53"

    // X.520 DN component
    case dmdName = "2.5.4.54"

    // X.520 DN component
    case clearance = "2.5.4.55"

    // X.520 DN component
    case defaultDirQop = "2.5.4.56"

    // X.520 DN component
    case attributeIntegrityInfo = "2.5.4.57"

    // X.520 DN component
    case attributeCertificate = "2.5.4.58"

    // X.520 DN component
    case attributeCertificateRevocationList = "2.5.4.59"

    // X.520 DN component
    case confKeyInfo = "2.5.4.60"

    // X.520 DN component
    case aACertificate = "2.5.4.61"

    // X.520 DN component
    case attributeDescriptorCertificate = "2.5.4.62"

    // X.520 DN component
    case attributeAuthorityRevocationList = "2.5.4.63"

    // X.520 DN component
    case familyInformation = "2.5.4.64"

    // X.520 DN component
    case pseudonym = "2.5.4.65"

    // X.520 DN component
    case communicationsService = "2.5.4.66"

    // X.520 DN component
    case communicationsNetwork = "2.5.4.67"

    // X.520 DN component
    case certificationPracticeStmt = "2.5.4.68"

    // X.520 DN component
    case certificatePolicy = "2.5.4.69"

    // X.520 DN component
    case pkiPath = "2.5.4.70"

    // X.520 DN component
    case privPolicy = "2.5.4.71"

    // X.520 DN component
    case role = "2.5.4.72"

    // X.520 DN component
    case delegationPath = "2.5.4.73"

    // X.520 DN component
    case protPrivPolicy = "2.5.4.74"

    // X.520 DN component
    case xMLPrivilegeInfo = "2.5.4.75"

    // X.520 DN component
    case xmlPrivPolicy = "2.5.4.76"

    // X.520 DN component
    case uuidpair = "2.5.4.77"

    // X.520 DN component
    case tagOid = "2.5.4.78"

    // X.520 DN component
    case uiiFormat = "2.5.4.79"

    // X.520 DN component
    case uiiInUrh = "2.5.4.80"

    // X.520 DN component
    case contentUrl = "2.5.4.81"

    // X.520 DN component
    case permission = "2.5.4.82"

    // X.520 DN component
    case uri = "2.5.4.83"

    // X.520 DN component
    case pwdAttribute = "2.5.4.84"

    // X.520 DN component
    case userPwd = "2.5.4.85"

    // X.520 DN component
    case urn = "2.5.4.86"

    // X.520 DN component
    case url = "2.5.4.87"

    // X.520 DN component
    case utmCoordinates = "2.5.4.88"

    // X.520 DN component
    case urnC = "2.5.4.89"

    // X.520 DN component
    case uii = "2.5.4.90"

    // X.520 DN component
    case epc = "2.5.4.91"

    // X.520 DN component
    case tagAfi = "2.5.4.92"

    // X.520 DN component
    case epcFormat = "2.5.4.93"

    // X.520 DN component
    case epcInUrn = "2.5.4.94"

    // X.520 DN component
    case ldapUrl = "2.5.4.95"

    // X.520 DN component
    case tagLocation = "2.5.4.96"

    // X.520 DN component
    case organizationIdentifier = "2.5.4.97"

    // X.520 DN component
    case countryCode3c = "2.5.4.98"

    // X.520 DN component
    case countryCode3n = "2.5.4.99"

    // X.520 DN component
    case dnsName = "2.5.4.100"

    // X.520 DN component
    case eepkCertificateRevocationList = "2.5.4.101"

    // X.520 DN component
    case eeAttrCertificateRevocationList = "2.5.4.102"

    // X.520 DN component
    case supportedPublicKeyAlgorithms = "2.5.4.103"

    // X.520 DN component
    case intEmail = "2.5.4.104"

    // X.520 DN component
    case jid = "2.5.4.105"

    // X.520 DN component
    case objectIdentifier = "2.5.4.106"

    // X.500 object classes

    // X.520 objectClass
    case top = "2.5.6.0"

    // X.520 objectClass
    case alias = "2.5.6.1"

    // X.520 objectClass
    case country = "2.5.6.2"

    // X.520 objectClass
    case locality = "2.5.6.3"

    // X.520 objectClass
    case organization = "2.5.6.4"

    // X.520 objectClass
    case organizationalUnit = "2.5.6.5"

    // X.520 objectClass
    case person = "2.5.6.6"

    // X.520 objectClass
    case organizationalPerson = "2.5.6.7"

    // X.520 objectClass
    case organizationalRole = "2.5.6.8"

    // X.520 objectClass
    case groupOfNames = "2.5.6.9"

    // X.520 objectClass
    case residentialPerson = "2.5.6.10"

    // X.520 objectClass
    case applicationProcess = "2.5.6.11"

    // X.520 objectClass
    case applicationEntity = "2.5.6.12"

    // X.520 objectClass
    case dSA = "2.5.6.13"

    // X.520 objectClass
    case device = "2.5.6.14"

    // X.520 objectClass
    case strongAuthenticationUser = "2.5.6.15"

    // X.520 objectClass
    case certificateAuthority = "2.5.6.16"

    // X.520 objectClass
    case groupOfUniqueNames = "2.5.6.17"

    // X.520 objectClass
    case pkiUser = "2.5.6.21"

    // X.520 objectClass
    case pkiCA = "2.5.6.22"

    // X.500 algorithms

    // X.500 algorithms.  Ambiguous, since no padding rules specified
    @available(*, deprecated)
    case rsa = "2.5.8.1.1"

    // X.509.  Some of the smaller values are from early X.509 drafts with
    // cross-pollination from X9.55 and are now deprecated.  Alternative OIDs are
    // marked if these are known.  In some cases there are multiple generations of
    // superseded OIDs

    // X.509 extension.  Deprecated, use 2 5 29 35 instead
    // @available(*, deprecated)
    // case authorityKeyIdentifier = "2.5.29.1"

    // X.509 extension.  Obsolete, use keyUsage/extKeyUsage instead
    @available(*, deprecated)
    case keyAttributes = "2.5.29.2"

    // X.509 extension.  Deprecated, use 2 5 29 32 instead
    // @available(*, deprecated)
    // case certificatePolicies = "2.5.29.3"

    // X.509 extension.  Obsolete, use keyUsage/extKeyUsage instead
    @available(*, deprecated)
    case keyUsageRestriction = "2.5.29.4"

    // X.509 extension.  Deprecated, use 2 5 29 33 instead
    @available(*, deprecated)
    case policyMapping = "2.5.29.5"

    // X.509 extension.  Obsolete, use nameConstraints instead
    @available(*, deprecated)
    case subtreesConstraint = "2.5.29.6"

    // X.509 extension.  Deprecated, use 2 5 29 17 instead
    // @available(*, deprecated)
    // case subjectAltName = "2.5.29.7"

    // X.509 extension.  Deprecated, use 2 5 29 18 instead
    // @available(*, deprecated)
    // case issuerAltName = "2.5.29.8"

    // X.509 extension
    case subjectDirectoryAttributes = "2.5.29.9"

    // X.509 extension.  Deprecated, use 2 5 29 19 instead
    // @available(*, deprecated)
    // case basicConstraints = "2.5.29.10"

    // X.509 extension.  Deprecated, use 2 5 29 30 instead
    // @available(*, deprecated)
    // case nameConstraints = "2.5.29.11"

    // X.509 extension.  Deprecated, use 2 5 29 36 instead
    // @available(*, deprecated)
    // case policyConstraints = "2.5.29.12"

    // X.509 extension.  Deprecated, use 2 5 29 19 instead
    // @available(*, deprecated)
    // case basicConstraints = "2.5.29.13"

    // X.509 extension
    case subjectKeyIdentifier = "2.5.29.14"

    // X.509 extension
    case keyUsage = "2.5.29.15"

    // X.509 extension
    case privateKeyUsagePeriod = "2.5.29.16"

    // X.509 extension
    case subjectAltName = "2.5.29.17"

    // X.509 extension
    case issuerAltName = "2.5.29.18"

    // X.509 extension
    case basicConstraints = "2.5.29.19"

    // X.509 extension
    case cRLNumber = "2.5.29.20"

    // X.509 extension
    case cRLReason = "2.5.29.21"

    // X.509 extension.  Deprecated, alternative OID uncertain
    @available(*, deprecated)
    case expirationDate = "2.5.29.22"

    // X.509 extension
    case instructionCode = "2.5.29.23"

    // X.509 extension
    case invalidityDate = "2.5.29.24"

    // X.509 extension.  Deprecated, use 2 5 29 31 instead
    // @available(*, deprecated)
    // case cRLDistributionPoints = "2.5.29.25"

    // X.509 extension.  Deprecated, use 2 5 29 28 instead
    // @available(*, deprecated)
    // case issuingDistributionPoint = "2.5.29.26"

    // X.509 extension
    case deltaCRLIndicator = "2.5.29.27"

    // X.509 extension
    case issuingDistributionPoint = "2.5.29.28"

    // X.509 extension
    case certificateIssuer = "2.5.29.29"

    // X.509 extension
    case nameConstraints = "2.5.29.30"

    // X.509 extension
    case cRLDistributionPoints = "2.5.29.31"

    // X.509 extension
    case certificatePolicies = "2.5.29.32"

    // X.509 certificate policy
    case anyPolicy = "2.5.29.32.0"

    // X.509 extension
    case policyMappings = "2.5.29.33"

    // X.509 extension.  Deprecated, use 2 5 29 36 instead
    // @available(*, deprecated)
    // case policyConstraints = "2.5.29.34"

    // X.509 extension
    case authorityKeyIdentifier = "2.5.29.35"

    // X.509 extension
    case policyConstraints = "2.5.29.36"

    // X.509 extension
    case extKeyUsage = "2.5.29.37"

    // X.509 extended key usage
    case anyExtendedKeyUsage = "2.5.29.37.0"

    // X.509 extension
    case authorityAttributeIdentifier = "2.5.29.38"

    // X.509 extension
    case roleSpecCertIdentifier = "2.5.29.39"

    // X.509 extension
    case cRLStreamIdentifier = "2.5.29.40"

    // X.509 extension
    case basicAttConstraints = "2.5.29.41"

    // X.509 extension
    case delegatedNameConstraints = "2.5.29.42"

    // X.509 extension
    case timeSpecification = "2.5.29.43"

    // X.509 extension
    case cRLScope = "2.5.29.44"

    // X.509 extension
    case statusReferrals = "2.5.29.45"

    // X.509 extension
    case freshestCRL = "2.5.29.46"

    // X.509 extension
    case orderedList = "2.5.29.47"

    // X.509 extension
    case attributeDescriptor = "2.5.29.48"

    // X.509 extension
    case userNotice = "2.5.29.49"

    // X.509 extension
    case sOAIdentifier = "2.5.29.50"

    // X.509 extension
    case baseUpdateTime = "2.5.29.51"

    // X.509 extension
    case acceptableCertPolicies = "2.5.29.52"

    // X.509 extension
    case deltaInfo = "2.5.29.53"

    // X.509 extension
    case inhibitAnyPolicy = "2.5.29.54"

    // X.509 extension
    case targetInformation = "2.5.29.55"

    // X.509 extension
    case noRevAvail = "2.5.29.56"

    // X.509 extension
    case acceptablePrivilegePolicies = "2.5.29.57"

    // X.509 extension
    case toBeRevoked = "2.5.29.58"

    // X.509 extension
    case revokedGroups = "2.5.29.59"

    // X.509 extension
    case expiredCertsOnCRL = "2.5.29.60"

    // X.509 extension
    case indirectIssuer = "2.5.29.61"

    // X.509 extension
    case noAssertion = "2.5.29.62"

    // X.509 extension
    case aAissuingDistributionPoint = "2.5.29.63"

    // X.509 extension
    case issuedOnBehalfOf = "2.5.29.64"

    // X.509 extension
    case singleUse = "2.5.29.65"

    // X.509 extension
    case groupAC = "2.5.29.66"

    // X.509 extension
    case allowedAttAss = "2.5.29.67"

    // X.509 extension
    case attributeMappings = "2.5.29.68"

    // X.509 extension
    case holderNameConstraints = "2.5.29.69"
}
