# NOCTYRA — Master Restricted Software & Information Agreement

**Document ID:** NCT-LEG-001  
**Revision:** 1.0  
**Status:** Private project agreement template  
**Handling:** Internal / Restricted Project Material  
**Effective date:** To be completed on execution

> This document is a formal project-governance template, not a government classification, military designation, export authorization, or security certification. It is not automatically binding merely because it is stored in a private repository. Complete the parties, schedules, jurisdiction and signatures, and obtain qualified legal review before use.

## 1. Parties and purpose
This Agreement governs access to NOCTYRA materials by a specifically identified recipient. It must be executed by the Owner and recipient.

**Owner:** Durvesh Mukund Jadhav or the lawful rights holder named in the executed copy.  
**Recipient:** To be completed.  
**Project:** NOCTYRA — Neural Obfuscation & Cryptographic Transmission Yielding Resilient Archives.

The purpose is to authorize narrowly scoped development, review, testing, or evaluation.

## 2. Definitions
"Project Materials" includes source code, binaries, build scripts, formats, protocols, architecture, diagrams, documentation, test fixtures, release artifacts, and non-public project data owned or controlled by the Owner.

"Confidential Information" means non-public Project Materials and information disclosed for the project, including credentials, key-management design, vulnerability reports, unreleased capabilities, and security procedures.

"Authorized Environment" means a repository, workstation, test system, or storage location specifically approved in writing.

"Authorized Purpose" means only the activity recorded in the recipient's written authorization.

"Security Incident" means suspected or actual unauthorized access, disclosure, alteration, loss, theft, or compromise of Project Materials, credentials, cryptographic material, or systems used to process them.

## 3. Authorization and access boundaries
3.1 Access is granted only to the named recipient after written approval.  
3.2 Access is limited to the least privilege necessary for the Authorized Purpose.  
3.3 Repository access does not grant ownership, distribution rights, sublicensing rights, or permission for unrelated use.  
3.4 The recipient shall not share credentials, invite additional users, mirror the repository, or move Materials to an unapproved environment.  
3.5 The Owner may maintain an access register recording approval, permissions, access dates, and revocation.  
3.6 Access may be suspended when reasonably necessary to protect the project or investigate compromise, subject to applicable law.

## 4. Confidentiality
4.1 The recipient shall use Confidential Information only for the Authorized Purpose.  
4.2 The recipient shall protect it with at least reasonable care and no less than the care used for similarly sensitive personal information.  
4.3 Disclosure to third parties requires prior written consent.  
4.4 Approved recipients must be bound by written obligations at least as protective as this Agreement.  
4.5 Confidential Information must not be posted to public issue trackers, public repositories, paste sites, public AI services, personal cloud storage, or unapproved collaboration tools.  
4.6 Exclusions apply to information demonstrably public without breach, lawfully known before disclosure, independently developed without use of Confidential Information, or lawfully received without a duty of confidence.  
4.7 For legally compelled disclosure, the recipient shall, where lawful, notify the Owner in advance and disclose only what is legally required.  
4.8 Confidentiality continues for five years after disclosure. Trade secrets remain protected for as long as they qualify under applicable law.

## 5. Intellectual property
5.1 Each party retains ownership of its pre-existing intellectual property.  
5.2 The Owner retains rights in Project Materials owned by the Owner.  
5.3 No ownership transfer occurs through access, review, testing, discussion, or contribution alone.  
5.4 Contributions require a separate written contributor agreement establishing any assignment or license.  
5.5 Contributors warrant that submitted materials are original or properly licensed and disclose third-party notices.  
5.6 No recipient may remove copyright, proprietary, attribution, or confidentiality notices.

## 6. Restrictions on use and disclosure
Except where a non-waivable legal right applies or written permission is granted, the recipient shall not:
- publish or distribute Materials beyond approved working copies;
- disclose source code, internal specifications, credentials, keys, or vulnerability details;
- sell, sublicense, rent, lease, host, or commercially exploit the Software;
- create derivative works outside the approved scope;
- provide Materials or project access to third parties;
- use project credentials for unrelated systems;
- bypass access controls or use another person's credentials;
- introduce backdoors, unauthorized telemetry, credential collection, or malicious code;
- misrepresent the project's certification, classification, or security status.

## 7. Secure handling requirements
7.1 Credentials and cryptographic secrets shall never be committed to source control.  
7.2 Passwords, API tokens, private keys, recovery secrets, and signing keys shall be stored only in approved secret-management facilities.  
7.3 Real personal documents, private archives, recovery materials, and sensitive carrier images shall not be used as repository test fixtures.  
7.4 Logs shall not expose passwords, keys, plaintext content, or unnecessary sensitive metadata.  
7.5 Temporary data shall be stored in approved locations and handled according to retention and deletion procedures.  
7.6 Recipients shall use multi-factor authentication where supported and maintain security updates on development devices.  
7.7 No recipient shall claim secure deletion from SSDs, cloud storage, backups, or version-control history without a verified mechanism.

## 8. Security incident response
8.1 The recipient shall promptly notify the Owner of a suspected Security Incident.  
8.2 Notice should include discovery time, affected systems/materials, known scope, containment actions, and follow-up contact.  
8.3 The recipient shall preserve relevant evidence where lawful and avoid unnecessary disclosure of sensitive material.  
8.4 Suspected compromised credentials shall be revoked or rotated.  
8.5 The recipient shall reasonably cooperate with containment, impact assessment, remediation, and legally required notifications.

## 9. Security testing and research
9.1 Testing is permitted only against builds and systems identified in writing.  
9.2 No authorization is granted to test third-party or production systems outside the approved scope.  
9.3 Findings shall be reported privately with sufficient detail for reproduction.  
9.4 Testing shall not intentionally disrupt services, destroy data, or expose personal information.  
9.5 Lawful security research and legally protected disclosures remain unaffected.

## 10. Third-party materials
Third-party dependencies remain governed by their respective licenses. The Owner shall maintain a dependency/license inventory and review compatibility before distribution. No clause overrides third-party rights or open-source obligations.

## 11. Assurance and representations
11.1 Internal assurance levels are project maturity labels only.  
11.2 They do not constitute government approval, military certification, formal classification, regulatory authorization, or independent security assurance.  
11.3 Any regulated or government deployment requires separate legal, technical, procurement, and authorization review by the competent organization.  
11.4 Recipients shall follow documented controls and report material deviations.

## 12. Term and termination
12.1 Authorization begins and ends on the dates stated in the signed authorization.  
12.2 Access may be suspended to protect the project or investigate compromise, subject to law.  
12.3 Material breach may result in termination subject to mandatory law and agreed notice/cure terms.  
12.4 On termination, the recipient shall cease use, return or delete Materials as instructed, revoke credentials, and certify completion where reasonably requested.  
12.5 Legally required retention remains subject to confidentiality.  
12.6 Ownership, confidentiality, third-party rights, disclaimers, liability, and provisions intended by nature to survive shall survive termination.

## 13. Disclaimers and liability
The Software is an early-stage private project unless a release is accompanied by a written assessment stating otherwise. No representation is made that it is error-free, audited, certified, classified, or suitable for a particular operational environment. To the maximum extent permitted by law, Materials are provided "AS IS". Nothing excludes liability that cannot lawfully be excluded.

## 14. Governing law and disputes
Governing law, courts, arbitration seat, language of proceedings, and notice addresses must be completed by qualified counsel for the relevant parties and jurisdictions. This template deliberately does not select a jurisdiction.

## 15. Required schedules
- **Schedule A:** Recipient legal identity and contact details
- **Schedule B:** Authorized repositories, branches, artifacts, and environments
- **Schedule C:** Permitted and prohibited activities
- **Schedule D:** Access start, expiry, and revocation
- **Schedule E:** Approved devices and storage locations
- **Schedule F:** Security incident reporting contacts
- **Schedule G:** Contribution and intellectual-property terms
- **Schedule H:** Governing law, venue, and dispute process

## 16. Execution

This template becomes an agreement only when completed and signed by the required parties.

**Owner / Rights Holder**  
Name: ______________________________  
Signature: ___________________________  
Date: _______________________________

**Authorized Recipient**  
Legal name: __________________________  
Organization: ________________________  
Signature: ___________________________  
Date: _______________________________

**Authorization reference:** __________________________

---

**End of document — NCT-LEG-001**
