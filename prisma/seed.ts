import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('Starting database seeding...');

  // Create users
  const hashedPassword = await bcrypt.hash('admin123', 10);
  const hashedPasswordStaff = await bcrypt.hash('staff123', 10);

  const admin = await prisma.user.upsert({
    where: { email: 'admin@medisentinel.com' },
    update: {},
    create: {
      email: 'admin@medisentinel.com',
      name: 'System Administrator',
      password: hashedPassword,
      role: 'admin',
      department: 'IT Security',
      isActive: true,
    },
  });

  const staff = await prisma.user.upsert({
    where: { email: 'staff@medisentinel.com' },
    update: {},
    create: {
      email: 'staff@medisentinel.com',
      name: 'IT Security Analyst',
      password: hashedPasswordStaff,
      role: 'staff',
      department: 'IT Operations',
      isActive: true,
    },
  });

  console.log('Users created:', { admin, staff });

  // Create Hospital Assets
  const assets = await Promise.all([
    prisma.asset.create({
      data: {
        name: 'EMR Main Server',
        type: 'server',
        ipAddress: '192.168.1.10',
        os: 'Ubuntu 22.04 LTS',
        status: 'active',
        criticality: 'critical',
        location: 'Data Center - Rack A1',
      },
    }),
    prisma.asset.create({
      data: {
        name: 'Lab Information System',
        type: 'server',
        ipAddress: '192.168.1.20',
        os: 'Windows Server 2022',
        status: 'active',
        criticality: 'high',
        location: 'Data Center - Rack B2',
      },
    }),
    prisma.asset.create({
      data: {
        name: 'Pharmacy Database Server',
        type: 'server',
        ipAddress: '192.168.1.30',
        os: 'CentOS 8',
        status: 'active',
        criticality: 'high',
        location: 'Data Center - Rack C3',
      },
    }),
    prisma.asset.create({
      data: {
        name: 'Radiology PACS Server',
        type: 'server',
        ipAddress: '192.168.1.40',
        os: 'Windows Server 2019',
        status: 'active',
        criticality: 'critical',
        location: 'Data Center - Rack D4',
      },
    }),
    prisma.asset.create({
      data: {
        name: 'Outpatient EMR Terminal',
        type: 'workstation',
        ipAddress: '192.168.2.101',
        os: 'Windows 11 Pro',
        status: 'active',
        criticality: 'medium',
        location: 'Outpatient Wing - Counter 1',
      },
    }),
    prisma.asset.create({
      data: {
        name: 'Emergency Room Terminal',
        type: 'workstation',
        ipAddress: '192.168.2.201',
        os: 'Windows 11 Pro',
        status: 'active',
        criticality: 'high',
        location: 'Emergency Department - Triage',
      },
    }),
    prisma.asset.create({
      data: {
        name: 'Lab Analyzer Workstation',
        type: 'lab-machine',
        ipAddress: '192.168.3.50',
        os: 'Windows 10 IoT',
        status: 'active',
        criticality: 'high',
        location: 'Laboratory - Analysis Room',
      },
    }),
    prisma.asset.create({
      data: {
        name: 'Core Firewall',
        type: 'firewall',
        ipAddress: '192.168.0.1',
        os: 'FortiOS',
        status: 'active',
        criticality: 'critical',
        location: 'Network Core',
      },
    }),
    prisma.asset.create({
      data: {
        name: 'Main Router',
        type: 'router',
        ipAddress: '192.168.0.254',
        os: 'Cisco IOS',
        status: 'active',
        criticality: 'critical',
        location: 'Network Core',
      },
    }),
    prisma.asset.create({
      data: {
        name: 'Backup Server',
        type: 'server',
        ipAddress: '192.168.1.50',
        os: 'Ubuntu 22.04 LTS',
        status: 'maintenance',
        criticality: 'medium',
        location: 'Data Center - Rack E5',
      },
    }),
  ]);

  console.log('Assets created:', assets.length);

  // Create Vulnerabilities
  const vulnerabilities = await Promise.all([
    prisma.vulnerability.create({
      data: {
        cveId: 'CVE-2024-1234',
        title: 'Remote Code Execution in EMR System',
        description: 'A critical RCE vulnerability exists in the EMR web interface allowing unauthenticated attackers to execute arbitrary code.',
        severity: 'critical',
        cvssScore: 9.8,
        publishedDate: new Date('2024-01-15'),
        exploitStatus: 'active',
        solution: 'Apply security patch v2.3.1 immediately',
        assetId: assets[0].id,
      },
    }),
    prisma.vulnerability.create({
      data: {
        cveId: 'CVE-2024-2345',
        title: 'SQL Injection in Lab Information System',
        description: 'SQL injection vulnerability in the lab results search functionality.',
        severity: 'high',
        cvssScore: 8.5,
        publishedDate: new Date('2024-02-20'),
        exploitStatus: 'poc',
        solution: 'Update to version 3.2.0 and implement input validation',
        assetId: assets[1].id,
      },
    }),
    prisma.vulnerability.create({
      data: {
        cveId: 'CVE-2024-3456',
        title: 'Privilege Escalation in Pharmacy Database',
        description: 'Local privilege escalation vulnerability allowing standard users to gain administrative access.',
        severity: 'high',
        cvssScore: 7.8,
        publishedDate: new Date('2024-03-10'),
        exploitStatus: 'weaponized',
        solution: 'Apply OS security updates and restrict user permissions',
        assetId: assets[2].id,
      },
    }),
    prisma.vulnerability.create({
      data: {
        cveId: 'CVE-2024-4567',
        title: 'Denial of Service in PACS Server',
        description: 'Memory exhaustion vulnerability can be triggered to cause service disruption.',
        severity: 'medium',
        cvssScore: 6.5,
        publishedDate: new Date('2024-04-05'),
        exploitStatus: 'unknown',
        solution: 'Apply patch v1.8.3 and configure memory limits',
        assetId: assets[3].id,
      },
    }),
    prisma.vulnerability.create({
      data: {
        cveId: 'CVE-2024-5678',
        title: 'Cross-Site Scripting in Patient Portal',
        description: 'Stored XSS vulnerability allows attackers to inject malicious scripts.',
        severity: 'medium',
        cvssScore: 5.4,
        publishedDate: new Date('2024-04-15'),
        exploitStatus: 'poc',
        solution: 'Implement proper output encoding and CSP headers',
        assetId: assets[4].id,
      },
    }),
  ]);

  console.log('Vulnerabilities created:', vulnerabilities.length);

  // Create Threats
  const threats = await Promise.all([
    prisma.threat.create({
      data: {
        name: 'Ransomware Attack Attempt',
        type: 'malware',
        severity: 'critical',
        status: 'active',
        description: 'Detected ransomware activity targeting EMR server from external IP.',
        sourceIp: '103.45.67.89',
        targetIp: '192.168.1.10',
        sourceCountry: 'Unknown',
        techniqueId: 'T1486',
        tacticId: 'TA0040',
        confidence: 0.85,
        isConfirmed: true,
        assetId: assets[0].id,
      },
    }),
    prisma.threat.create({
      data: {
        name: 'Phishing Campaign',
        type: 'phishing',
        severity: 'high',
        status: 'investigating',
        description: 'Multiple employees reporting suspicious emails claiming to be from IT support.',
        sourceIp: '45.33.21.98',
        techniqueId: 'T1566',
        tacticId: 'TA0001',
        confidence: 0.72,
        isConfirmed: false,
      },
    }),
    prisma.threat.create({
      data: {
        name: 'SQL Injection Attack',
        type: 'sql-injection',
        severity: 'high',
        status: 'mitigated',
        description: 'SQL injection attempt blocked by WAF on Lab Information System.',
        sourceIp: '89.45.123.67',
        targetIp: '192.168.1.20',
        sourceCountry: 'Russia',
        techniqueId: 'T1190',
        tacticId: 'TA0001',
        confidence: 0.91,
        isConfirmed: true,
        assetId: assets[1].id,
      },
    }),
    prisma.threat.create({
      data: {
        name: 'Brute Force Login Attempt',
        type: 'brute-force',
        severity: 'medium',
        status: 'active',
        description: 'Repeated failed login attempts detected on emergency room terminal.',
        sourceIp: '192.168.2.50',
        targetIp: '192.168.2.201',
        techniqueId: 'T1110',
        tacticId: 'TA0006',
        confidence: 0.88,
        isConfirmed: true,
        assetId: assets[5].id,
      },
    }),
    prisma.threat.create({
      data: {
        name: 'DDoS Attack on Firewall',
        type: 'ddos',
        severity: 'high',
        status: 'mitigated',
        description: 'Volumetric DDoS attack targeting external network interface.',
        sourceIp: 'Multiple',
        targetIp: '192.168.0.1',
        sourceCountry: 'China',
        techniqueId: 'T1498',
        tacticId: 'TA0040',
        confidence: 0.95,
        isConfirmed: true,
        assetId: assets[7].id,
      },
    }),
  ]);

  console.log('Threats created:', threats.length);

  // Create Mitigations
  const mitigations = await Promise.all([
    prisma.mitigation.create({
      data: {
        title: 'Patch EMR System RCE Vulnerability',
        description: 'Apply security patch v2.3.1 to address the RCE vulnerability',
        type: 'patch',
        priority: 'critical',
        status: 'pending',
        estimatedEffort: '2 hours',
        threatId: threats[0].id,
        vulnerabilityId: vulnerabilities[0].id,
        assignedTo: admin.id,
        dueDate: new Date(Date.now() + 24 * 60 * 60 * 1000), // Tomorrow
      },
    }),
    prisma.mitigation.create({
      data: {
        title: 'Block Malicious IP Addresses',
        description: 'Add firewall rules to block known malicious IP addresses',
        type: 'firewall',
        priority: 'high',
        status: 'in-progress',
        estimatedEffort: '1 hour',
        threatId: threats[2].id,
        assignedTo: staff.id,
        dueDate: new Date(Date.now() + 12 * 60 * 60 * 1000),
      },
    }),
    prisma.mitigation.create({
      data: {
        title: 'Conduct Phishing Awareness Training',
        description: 'Mandatory cybersecurity awareness training for all staff',
        type: 'training',
        priority: 'medium',
        status: 'pending',
        estimatedEffort: '4 hours',
        threatId: threats[1].id,
        assignedTo: admin.id,
        dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    }),
    prisma.mitigation.create({
      data: {
        title: 'Implement Account Lockout Policy',
        description: 'Configure account lockout after 5 failed login attempts',
        type: 'configuration',
        priority: 'high',
        status: 'pending',
        estimatedEffort: '30 minutes',
        threatId: threats[3].id,
        assignedTo: staff.id,
        dueDate: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    }),
    prisma.mitigation.create({
      data: {
        title: 'Apply SQL Injection Patch',
        description: 'Update Lab Information System to version 3.2.0',
        type: 'patch',
        priority: 'high',
        status: 'completed',
        estimatedEffort: '3 hours',
        threatId: threats[2].id,
        vulnerabilityId: vulnerabilities[1].id,
        assignedTo: staff.id,
        dueDate: new Date(Date.now() - 24 * 60 * 60 * 1000),
        completedAt: new Date(),
      },
    }),
  ]);

  console.log('Mitigations created:', mitigations.length);

  // Create Attack Logs
  const attackLogs = await Promise.all([
    prisma.attackLog.create({
      data: {
        attackType: 'Ransomware',
        severity: 'critical',
        sourceIp: '103.45.67.89',
        sourcePort: 54321,
        destinationIp: '192.168.1.10',
        destinationPort: 443,
        protocol: 'HTTPS',
        status: 'blocked',
        description: 'Malicious payload blocked by endpoint protection',
        assetId: assets[0].id,
        userId: admin.id,
        mitigated: true,
      },
    }),
    prisma.attackLog.create({
      data: {
        attackType: 'SQL Injection',
        severity: 'high',
        sourceIp: '89.45.123.67',
        sourcePort: 38475,
        destinationIp: '192.168.1.20',
        destinationPort: 80,
        protocol: 'HTTP',
        status: 'blocked',
        description: 'SQL injection payload detected and blocked by WAF',
        assetId: assets[1].id,
        userId: staff.id,
        mitigated: true,
      },
    }),
    prisma.attackLog.create({
      data: {
        attackType: 'Brute Force',
        severity: 'medium',
        sourceIp: '192.168.2.50',
        sourcePort: 52134,
        destinationIp: '192.168.2.201',
        destinationPort: 3389,
        protocol: 'RDP',
        status: 'detected',
        description: '15 failed RDP login attempts within 5 minutes',
        assetId: assets[5].id,
        mitigated: false,
      },
    }),
    prisma.attackLog.create({
      data: {
        attackType: 'DDoS',
        severity: 'high',
        sourceIp: 'Multiple',
        destinationIp: '192.168.0.1',
        destinationPort: 443,
        protocol: 'TCP',
        status: 'blocked',
        description: 'Volumetric attack mitigated by firewall',
        assetId: assets[7].id,
        userId: admin.id,
        mitigated: true,
      },
    }),
    prisma.attackLog.create({
      data: {
        attackType: 'Phishing',
        severity: 'high',
        sourceIp: '45.33.21.98',
        sourcePort: 25,
        destinationIp: '192.168.1.10',
        destinationPort: 443,
        protocol: 'SMTP/HTTPS',
        status: 'detected',
        description: 'Phishing email reported by multiple users',
        assetId: assets[0].id,
        mitigated: false,
      },
    }),
  ]);

  console.log('Attack logs created:', attackLogs.length);

  // Create Alerts
  const alerts = await Promise.all([
    prisma.alert.create({
      data: {
        type: 'dashboard',
        severity: 'critical',
        title: '🚨 CRITICAL: Ransomware Attack Detected',
        message: 'Ransomware activity detected on EMR Main Server. Immediate action required.',
        alertType: 'threat',
        threatId: threats[0].id,
        userId: admin.id,
      },
    }),
    prisma.alert.create({
      data: {
        type: 'email',
        severity: 'high',
        title: '⚠️ HIGH: SQL Injection Attempt Blocked',
        message: 'SQL injection attack blocked on Lab Information System',
        alertType: 'threat',
        threatId: threats[2].id,
        userId: staff.id,
      },
    }),
    prisma.alert.create({
      data: {
        type: 'sms',
        severity: 'high',
        title: '📱 ALERT: Multiple Brute Force Attempts',
        message: 'Brute force attack detected on Emergency Room Terminal',
        alertType: 'threat',
        userId: admin.id,
      },
    }),
    prisma.alert.create({
      data: {
        type: 'dashboard',
        severity: 'critical',
        title: '🔧 CRITICAL Vulnerability Found',
        message: 'CVE-2024-1234: Remote Code Execution in EMR System requires immediate patching',
        alertType: 'vulnerability',
        userId: admin.id,
      },
    }),
    prisma.alert.create({
      data: {
        type: 'email',
        severity: 'medium',
        title: '📊 Weekly Security Report Available',
        message: 'Your weekly threat intelligence report is ready for review',
        alertType: 'system',
        userId: staff.id,
      },
    }),
  ]);

  console.log('Alerts created:', alerts.length);

  // Create Risk Scores
  const riskScores = await Promise.all([
    prisma.riskScore.create({
      data: {
        assetId: assets[0].id,
        threatType: 'malware',
        overallScore: 85,
        threatScore: 90,
        vulnerabilityScore: 95,
        assetCriticalityScore: 95,
        trend: 'increasing',
      },
    }),
    prisma.riskScore.create({
      data: {
        assetId: assets[1].id,
        threatType: 'sql-injection',
        overallScore: 72,
        threatScore: 75,
        vulnerabilityScore: 85,
        assetCriticalityScore: 80,
        trend: 'stable',
      },
    }),
    prisma.riskScore.create({
      data: {
        assetId: assets[3].id,
        threatType: 'ddos',
        overallScore: 65,
        threatScore: 70,
        vulnerabilityScore: 60,
        assetCriticalityScore: 95,
        trend: 'decreasing',
      },
    }),
  ]);

  console.log('Risk scores created:', riskScores.length);

  // Create Reports
  const reports = await Promise.all([
    prisma.report.create({
      data: {
        title: 'Daily Threat Intelligence Report - May 15, 2024',
        type: 'daily',
        summary: '5 new threats detected, 2 critical vulnerabilities identified, overall risk score: 72',
        threatCount: 5,
        vulnerabilityCount: 2,
        riskScore: 72,
        generatedBy: admin.name,
      },
    }),
    prisma.report.create({
      data: {
        title: 'Weekly Security Summary - Week 19, 2024',
        type: 'weekly',
        summary: '23 total threats this week, 12 mitigated successfully, 3 active investigations',
        threatCount: 23,
        vulnerabilityCount: 8,
        riskScore: 68,
        generatedBy: admin.name,
      },
    }),
    prisma.report.create({
      data: {
        title: 'Incident Report: Ransomware Attack Attempt',
        type: 'incident',
        summary: 'Ransomware attack detected and blocked on EMR server. No data exfiltration confirmed.',
        threatCount: 1,
        vulnerabilityCount: 1,
        riskScore: 85,
        generatedBy: staff.name,
      },
    }),
  ]);

  console.log('Reports created:', reports.length);

  // Create MITRE ATT&CK entries
  const mitreAttacks = await Promise.all([
    prisma.mitreAttack.create({
      data: {
        techniqueId: 'T1486',
        tacticId: 'TA0040',
        name: 'Data Encrypted for Impact',
        description: 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.',
        category: 'impact',
        detection: 'Monitor for file system modifications, particularly encryption operations',
        mitigation: 'Implement backups, file integrity monitoring, and endpoint protection',
      },
    }),
    prisma.mitreAttack.create({
      data: {
        techniqueId: 'T1566',
        tacticId: 'TA0001',
        name: 'Phishing',
        description: 'Adversaries may send phishing messages to gain access to victim systems.',
        category: 'initial-access',
        detection: 'Monitor for suspicious emails, analyze email headers and content',
        mitigation: 'Implement email filtering, user training, and multi-factor authentication',
      },
    }),
    prisma.mitreAttack.create({
      data: {
        techniqueId: 'T1190',
        tacticId: 'TA0001',
        name: 'Exploit Public-Facing Application',
        description: 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.',
        category: 'initial-access',
        detection: 'Monitor web application logs for exploit attempts',
        mitigation: 'Keep systems patched, use WAF, implement input validation',
      },
    }),
    prisma.mitreAttack.create({
      data: {
        techniqueId: 'T1110',
        tacticId: 'TA0006',
        name: 'Brute Force',
        description: 'Adversaries may use brute force techniques to gain access to accounts.',
        category: 'credential-access',
        detection: 'Monitor for repeated failed login attempts',
        mitigation: 'Implement account lockout, MFA, and strong password policies',
      },
    }),
    prisma.mitreAttack.create({
      data: {
        techniqueId: 'T1498',
        tacticId: 'TA0040',
        name: 'Network Denial of Service',
        description: 'Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources.',
        category: 'impact',
        detection: 'Monitor for abnormal traffic patterns and network saturation',
        mitigation: 'Implement DDoS protection, rate limiting, and traffic filtering',
      },
    }),
  ]);

  console.log('MITRE ATT&CK entries created:', mitreAttacks.length);

  console.log('Database seeding completed successfully!');
}

main()
  .catch((e) => {
    console.error('Error seeding database:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
