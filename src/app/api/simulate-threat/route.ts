import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

const threatTypes = ['malware', 'phishing', 'ddos', 'sql-injection', 'brute-force', 'xss'];
const severities = ['critical', 'high', 'medium', 'low'];
const countries = ['China', 'Russia', 'USA', 'Unknown', 'Brazil', 'India', 'Germany'];

const threatNames = {
  'malware': ['Ransomware Attack', 'Trojan Infection', 'Spyware Detection', 'Botnet Activity'],
  'phishing': ['Phishing Campaign', 'Spear Phishing', 'Business Email Compromise'],
  'ddos': ['DDoS Attack', 'Volumetric Flood', 'SYN Flood Attack'],
  'sql-injection': ['SQL Injection', 'Blind SQL Injection', 'Union-based SQLi'],
  'brute-force': ['Brute Force Login', 'Credential Stuffing', 'Password Spray'],
  'xss': ['Cross-Site Scripting', 'Stored XSS', 'Reflected XSS'],
};

const techniques = {
  'malware': { id: 'T1486', tactic: 'TA0040' },
  'phishing': { id: 'T1566', tactic: 'TA0001' },
  'ddos': { id: 'T1498', tactic: 'TA0040' },
  'sql-injection': { id: 'T1190', tactic: 'TA0001' },
  'brute-force': { id: 'T1110', tactic: 'TA0006' },
  'xss': { id: 'T1059', tactic: 'TA0002' },
};

export async function POST(request: NextRequest) {
  try {
    // Simulate a new threat detection
    const type = threatTypes[Math.floor(Math.random() * threatTypes.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const names = threatNames[type as keyof typeof threatNames];
    const name = names[Math.floor(Math.random() * names.length)];
    const country = countries[Math.floor(Math.random() * countries.length)];
    const technique = techniques[type as keyof typeof techniques];

    // Generate random IP
    const sourceIp = `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;

    // Get a random asset
    const assets = await db.asset.findMany({ where: { status: 'active' } });
    const asset = assets[Math.floor(Math.random() * assets.length)];

    // Create the threat
    const threat = await db.threat.create({
      data: {
        name,
        type,
        severity,
        status: 'active',
        description: `Simulated ${type} attack detected from ${country}. Automated analysis in progress.`,
        sourceIp,
        targetIp: asset?.ipAddress || null,
        sourceCountry: country,
        techniqueId: technique.id,
        tacticId: technique.tactic,
        confidence: Math.random() * 0.4 + 0.6, // 0.6 to 1.0
        isConfirmed: Math.random() > 0.3,
        assetId: asset?.id || null,
      },
    });

    // Create corresponding alert
    const alertTypes = ['dashboard', 'email', 'sms'];
    const alertType = alertTypes[Math.floor(Math.random() * alertTypes.length)];

    await db.alert.create({
      data: {
        type: alertType,
        severity,
        title: `🚨 ${severity.toUpperCase()}: ${name}`,
        message: `${name} detected from ${sourceIp} (${country}). Immediate investigation recommended.`,
        alertType: 'threat',
        threatId: threat.id,
      },
    });

    // Create attack log
    await db.attackLog.create({
      data: {
        attackType: type,
        severity,
        sourceIp,
        sourcePort: Math.floor(Math.random() * 65535),
        destinationIp: asset?.ipAddress || null,
        destinationPort: [80, 443, 22, 3389, 8080][Math.floor(Math.random() * 5)],
        protocol: ['TCP', 'UDP', 'HTTP', 'HTTPS'][Math.floor(Math.random() * 4)],
        status: 'detected',
        description: `Automated detection of ${type} attack`,
        assetId: asset?.id || null,
        mitigated: false,
      },
    });

    return NextResponse.json({ success: true, threat });
  } catch (error) {
    console.error('Error simulating threat:', error);
    return NextResponse.json(
      { error: 'Failed to simulate threat' },
      { status: 500 }
    );
  }
}
