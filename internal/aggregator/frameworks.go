package aggregator

// FrameworkDefinition describes a compliance framework and its controls.
type FrameworkDefinition struct {
	ID          string
	Name        string
	Description string
	Controls    []ControlDefinition
}

// ControlDefinition describes a single control within a framework.
type ControlDefinition struct {
	ID          string
	Name        string
	Description string
	Category    string
}

// SOC2 Trust Service Criteria
var SOC2Framework = FrameworkDefinition{
	ID:          "SOC2",
	Name:        "SOC 2 Type II",
	Description: "AICPA Trust Service Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy",
	Controls: []ControlDefinition{
		{ID: "SOC2-CC1.1", Name: "COSO Principle 1", Description: "The entity demonstrates a commitment to integrity and ethical values", Category: "Control Environment"},
		{ID: "SOC2-CC2.1", Name: "COSO Principle 13", Description: "The entity obtains or generates and uses relevant, quality information", Category: "Communication and Information"},
		{ID: "SOC2-CC3.1", Name: "COSO Principle 6", Description: "The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks", Category: "Risk Assessment"},
		{ID: "SOC2-CC4.1", Name: "COSO Principle 16", Description: "The entity selects, develops, and performs ongoing and/or separate evaluations", Category: "Monitoring Activities"},
		{ID: "SOC2-CC5.1", Name: "COSO Principle 10", Description: "The entity selects and develops control activities that contribute to the mitigation of risks", Category: "Control Activities"},
		{ID: "SOC2-CC6.1", Name: "Logical and Physical Access", Description: "The entity implements logical access security software, infrastructure, and architectures", Category: "Logical and Physical Access Controls"},
		{ID: "SOC2-CC6.2", Name: "User Authentication", Description: "Prior to issuing system credentials, the entity registers and authorizes new users", Category: "Logical and Physical Access Controls"},
		{ID: "SOC2-CC6.3", Name: "Least Privilege", Description: "The entity authorizes, modifies, or removes access to data based on roles", Category: "Logical and Physical Access Controls"},
		{ID: "SOC2-CC6.6", Name: "Network Security", Description: "The entity implements logical access security measures to protect against threats from outside its system boundaries", Category: "Logical and Physical Access Controls"},
		{ID: "SOC2-CC6.7", Name: "Data Transmission", Description: "The entity restricts the transmission of data to authorized channels", Category: "Logical and Physical Access Controls"},
		{ID: "SOC2-CC6.8", Name: "Malicious Software Prevention", Description: "The entity implements controls to prevent or detect and act upon the introduction of unauthorized software", Category: "Logical and Physical Access Controls"},
		{ID: "SOC2-CC7.1", Name: "Vulnerability Management", Description: "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in vulnerabilities", Category: "System Operations"},
		{ID: "SOC2-CC7.2", Name: "Security Monitoring", Description: "The entity monitors system components and the operation of those components for anomalies", Category: "System Operations"},
		{ID: "SOC2-CC7.3", Name: "Security Incident Response", Description: "The entity evaluates security events to determine whether they could or have resulted in incidents", Category: "System Operations"},
		{ID: "SOC2-CC8.1", Name: "Change Management", Description: "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure and software", Category: "Change Management"},
		{ID: "SOC2-A1.1", Name: "Availability Commitments", Description: "The entity maintains, monitors, and evaluates current processing capacity and use of system components", Category: "Availability"},
		{ID: "SOC2-A1.2", Name: "Data Recovery", Description: "The entity authorizes, designs, develops, implements, operates, approves, maintains, and monitors environmental protections, software, data backup, and recovery", Category: "Availability"},
		{ID: "SOC2-C1.1", Name: "Confidentiality Classification", Description: "The entity identifies and maintains confidential information", Category: "Confidentiality"},
	},
}

// NIST 800-53 Rev 5 Control Families (selected key controls)
var NISTFramework = FrameworkDefinition{
	ID:          "NIST-800-53",
	Name:        "NIST SP 800-53 Rev 5",
	Description: "Security and Privacy Controls for Information Systems and Organizations",
	Controls: []ControlDefinition{
		{ID: "NIST-AC-2", Name: "Account Management", Description: "Manage system accounts, group memberships, privileges, and access authorizations", Category: "Access Control"},
		{ID: "NIST-AC-3", Name: "Access Enforcement", Description: "Enforce approved authorizations for logical access to information and system resources", Category: "Access Control"},
		{ID: "NIST-AC-4", Name: "Information Flow Enforcement", Description: "Enforce approved authorizations for controlling the flow of information within the system and between systems", Category: "Access Control"},
		{ID: "NIST-AC-6", Name: "Least Privilege", Description: "Employ the principle of least privilege, allowing only authorized accesses", Category: "Access Control"},
		{ID: "NIST-AU-2", Name: "Audit Events", Description: "Identify the types of events that the system is capable of logging", Category: "Audit and Accountability"},
		{ID: "NIST-AU-3", Name: "Content of Audit Records", Description: "Ensure that audit records contain the necessary information", Category: "Audit and Accountability"},
		{ID: "NIST-AU-9", Name: "Protection of Audit Information", Description: "Protect audit information and audit logging tools from unauthorized access", Category: "Audit and Accountability"},
		{ID: "NIST-CM-6", Name: "Configuration Settings", Description: "Establish and document configuration settings for IT products", Category: "Configuration Management"},
		{ID: "NIST-CM-7", Name: "Least Functionality", Description: "Configure the system to provide only mission-essential capabilities", Category: "Configuration Management"},
		{ID: "NIST-CP-9", Name: "System Backup", Description: "Conduct backups of system-level and user-level information", Category: "Contingency Planning"},
		{ID: "NIST-IA-2", Name: "Identification and Authentication", Description: "Uniquely identify and authenticate organizational users", Category: "Identification and Authentication"},
		{ID: "NIST-IA-5", Name: "Authenticator Management", Description: "Manage system authenticators by verifying identity before issuing", Category: "Identification and Authentication"},
		{ID: "NIST-SA-11", Name: "Developer Testing and Evaluation", Description: "Require the developer to create a security assessment plan", Category: "System and Services Acquisition"},
		{ID: "NIST-SC-6", Name: "Resource Availability", Description: "Protect the availability of resources by allocating processor and memory limits", Category: "System and Communications Protection"},
		{ID: "NIST-SC-7", Name: "Boundary Protection", Description: "Monitor and control communications at the external managed interfaces of the system", Category: "System and Communications Protection"},
		{ID: "NIST-SC-8", Name: "Transmission Confidentiality", Description: "Protect the confidentiality of transmitted information", Category: "System and Communications Protection"},
		{ID: "NIST-SC-17", Name: "PKI Certificates", Description: "Issue public key certificates under an appropriate certificate policy", Category: "System and Communications Protection"},
		{ID: "NIST-SC-20", Name: "Secure Name/Address Resolution", Description: "Provide data origin authentication and data integrity verification for DNS", Category: "System and Communications Protection"},
		{ID: "NIST-SC-28", Name: "Protection of Information at Rest", Description: "Protect the confidentiality and integrity of information at rest", Category: "System and Communications Protection"},
		{ID: "NIST-SI-2", Name: "Flaw Remediation", Description: "Identify, report, and correct system flaws", Category: "System and Information Integrity"},
		{ID: "NIST-SI-10", Name: "Information Input Validation", Description: "Check the validity of information inputs", Category: "System and Information Integrity"},
	},
}

// PCI DSS v4.0 Requirements
var PCIDSSFramework = FrameworkDefinition{
	ID:          "PCI-DSS",
	Name:        "PCI DSS v4.0",
	Description: "Payment Card Industry Data Security Standard",
	Controls: []ControlDefinition{
		{ID: "PCI-DSS-1.1", Name: "Network Security Controls", Description: "Processes and mechanisms for network security controls are defined and understood", Category: "Requirement 1: Network Security"},
		{ID: "PCI-DSS-1.2", Name: "Network Access Restrictions", Description: "Network security controls are configured and maintained", Category: "Requirement 1: Network Security"},
		{ID: "PCI-DSS-1.3", Name: "Network Segmentation", Description: "Network access to and from the cardholder data environment is restricted", Category: "Requirement 1: Network Security"},
		{ID: "PCI-DSS-2.2.2", Name: "Unnecessary Services", Description: "Only necessary services, protocols, daemons, and functions are enabled", Category: "Requirement 2: Secure Configuration"},
		{ID: "PCI-DSS-3.4", Name: "Encryption at Rest", Description: "Primary account numbers are secured with strong cryptography wherever stored", Category: "Requirement 3: Protect Stored Data"},
		{ID: "PCI-DSS-4.1", Name: "Encryption in Transit", Description: "Strong cryptography is used to safeguard PAN during transmission over open networks", Category: "Requirement 4: Encrypt Transmission"},
		{ID: "PCI-DSS-6.2", Name: "Patch Management", Description: "Bespoke and custom software are developed securely", Category: "Requirement 6: Secure Development"},
		{ID: "PCI-DSS-6.5", Name: "Secure Coding", Description: "Changes to all system components are managed securely", Category: "Requirement 6: Secure Development"},
		{ID: "PCI-DSS-7.1", Name: "Access Control", Description: "Processes and mechanisms for restricting access are defined and understood", Category: "Requirement 7: Restrict Access"},
		{ID: "PCI-DSS-8.2", Name: "Password Requirements", Description: "User identification and related accounts are strictly managed", Category: "Requirement 8: Identify Users"},
		{ID: "PCI-DSS-8.2.4", Name: "Password Rotation", Description: "Passwords/passphrases are changed at least once every 90 days", Category: "Requirement 8: Identify Users"},
		{ID: "PCI-DSS-8.3", Name: "MFA", Description: "Multi-factor authentication is implemented to secure access", Category: "Requirement 8: Identify Users"},
		{ID: "PCI-DSS-8.1.4", Name: "Inactive Accounts", Description: "Inactive user accounts are removed or disabled within 90 days", Category: "Requirement 8: Identify Users"},
		{ID: "PCI-DSS-10.1", Name: "Audit Trails", Description: "Processes and mechanisms for logging and monitoring are defined and documented", Category: "Requirement 10: Log and Monitor"},
		{ID: "PCI-DSS-10.2", Name: "Audit Log Content", Description: "Audit logs are implemented to support the detection of anomalies and suspicious activity", Category: "Requirement 10: Log and Monitor"},
		{ID: "PCI-DSS-10.5", Name: "Audit Log Integrity", Description: "Audit logs are secured so they cannot be altered", Category: "Requirement 10: Log and Monitor"},
		{ID: "PCI-DSS-12.10", Name: "Incident Response", Description: "Security incidents and suspected security incidents are responded to immediately", Category: "Requirement 12: Security Policy"},
	},
}

// CIS Benchmarks (cross-platform identifiers)
var CISFramework = FrameworkDefinition{
	ID:          "CIS",
	Name:        "CIS Benchmarks",
	Description: "Center for Internet Security Benchmarks for AWS, Linux, Docker, and GitHub",
	Controls: []ControlDefinition{
		// AWS
		{ID: "CIS-AWS-1.5", Name: "Root MFA", Description: "Ensure MFA is enabled for the root account", Category: "CIS AWS - IAM"},
		{ID: "CIS-AWS-1.8", Name: "Password Policy", Description: "Ensure IAM password policy requires minimum length", Category: "CIS AWS - IAM"},
		{ID: "CIS-AWS-1.10", Name: "User MFA", Description: "Ensure MFA is enabled for all IAM users with console access", Category: "CIS AWS - IAM"},
		{ID: "CIS-AWS-1.12", Name: "Unused Credentials", Description: "Ensure credentials unused for 90 days are disabled", Category: "CIS AWS - IAM"},
		{ID: "CIS-AWS-1.14", Name: "Key Rotation", Description: "Ensure access keys are rotated every 90 days", Category: "CIS AWS - IAM"},
		{ID: "CIS-AWS-2.1.1", Name: "S3 Encryption", Description: "Ensure S3 bucket default encryption is enabled", Category: "CIS AWS - Storage"},
		{ID: "CIS-AWS-2.1.2", Name: "S3 Public Access", Description: "Ensure S3 bucket public access is blocked", Category: "CIS AWS - Storage"},
		{ID: "CIS-AWS-2.1.3", Name: "S3 Versioning", Description: "Ensure S3 bucket versioning is enabled", Category: "CIS AWS - Storage"},
		{ID: "CIS-AWS-2.1.4", Name: "S3 Logging", Description: "Ensure S3 bucket logging is enabled", Category: "CIS AWS - Storage"},
		{ID: "CIS-AWS-2.2.1", Name: "EBS Encryption", Description: "Ensure EBS volume encryption is enabled", Category: "CIS AWS - Storage"},
		{ID: "CIS-AWS-2.3.1", Name: "RDS Encryption", Description: "Ensure RDS encryption is enabled", Category: "CIS AWS - Storage"},
		{ID: "CIS-AWS-3.1", Name: "CloudTrail Enabled", Description: "Ensure CloudTrail is enabled in all regions", Category: "CIS AWS - Logging"},
		{ID: "CIS-AWS-3.2", Name: "CloudTrail Log Validation", Description: "Ensure CloudTrail log file validation is enabled", Category: "CIS AWS - Logging"},
		{ID: "CIS-AWS-5.2", Name: "No Unrestricted SSH", Description: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", Category: "CIS AWS - Networking"},
		{ID: "CIS-AWS-5.3", Name: "No Unrestricted RDP", Description: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", Category: "CIS AWS - Networking"},
		// Linux
		{ID: "CIS-Linux-2.1", Name: "Unnecessary Services", Description: "Ensure unnecessary services are removed or masked", Category: "CIS Linux - Services"},
		{ID: "CIS-Linux-3.1", Name: "Network Parameters", Description: "Ensure kernel network parameters are set", Category: "CIS Linux - Network"},
		{ID: "CIS-Linux-3.5", Name: "Firewall", Description: "Ensure firewall is active", Category: "CIS Linux - Network"},
		{ID: "CIS-Linux-4.1", Name: "Audit System", Description: "Ensure auditing is enabled", Category: "CIS Linux - Logging"},
		{ID: "CIS-Linux-5.1", Name: "Cron Permissions", Description: "Ensure cron daemon is enabled and permissions are configured", Category: "CIS Linux - Access"},
		{ID: "CIS-Linux-6.1", Name: "File Permissions", Description: "Ensure system file permissions are configured", Category: "CIS Linux - Maintenance"},
		{ID: "CIS-Linux-6.2", Name: "User Accounts", Description: "Ensure user and group settings are configured", Category: "CIS Linux - Maintenance"},
		// Docker
		{ID: "CIS-Docker-2.1", Name: "Daemon Configuration", Description: "Ensure Docker daemon configuration is secure", Category: "CIS Docker - Daemon"},
		{ID: "CIS-Docker-2.12", Name: "Logging", Description: "Ensure container logging is configured", Category: "CIS Docker - Daemon"},
		{ID: "CIS-Docker-4.1", Name: "Image Provenance", Description: "Ensure container images are scanned for vulnerabilities", Category: "CIS Docker - Images"},
		{ID: "CIS-Docker-5.1", Name: "Container Privileges", Description: "Ensure containers do not run in privileged mode", Category: "CIS Docker - Runtime"},
		{ID: "CIS-Docker-5.7", Name: "Container Networking", Description: "Ensure container port mapping is configured correctly", Category: "CIS Docker - Runtime"},
		{ID: "CIS-Docker-5.10", Name: "Resource Limits", Description: "Ensure memory and CPU limits are set", Category: "CIS Docker - Runtime"},
		// GitHub
		{ID: "CIS-GitHub-1.1", Name: "Org 2FA", Description: "Ensure 2FA is enforced for the organization", Category: "CIS GitHub - Authentication"},
		{ID: "CIS-GitHub-1.2", Name: "Repo Visibility", Description: "Ensure repositories are not unintentionally public", Category: "CIS GitHub - Access"},
		{ID: "CIS-GitHub-1.3", Name: "Secret Scanning", Description: "Ensure secret scanning is enabled", Category: "CIS GitHub - Code Security"},
		{ID: "CIS-GitHub-2.1", Name: "Dependabot", Description: "Ensure Dependabot alerts are enabled and reviewed", Category: "CIS GitHub - Supply Chain"},
		{ID: "CIS-GitHub-3.1", Name: "Actions Security", Description: "Ensure GitHub Actions permissions are restrictive", Category: "CIS GitHub - CI/CD"},
	},
}

// AllFrameworks returns every framework definition.
func AllFrameworks() []FrameworkDefinition {
	return []FrameworkDefinition{SOC2Framework, NISTFramework, PCIDSSFramework, CISFramework}
}
