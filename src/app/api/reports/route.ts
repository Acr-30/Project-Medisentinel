import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET() {
  try {
    const reports = await db.report.findMany({
      orderBy: { generatedAt: 'desc' },
    });

    return NextResponse.json({ reports });
  } catch (error) {
    console.error('Error fetching reports:', error);
    return NextResponse.json(
      { error: 'Failed to fetch reports' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { type } = await request.json();

    // Gather data for the report
    const [threats, vulnerabilities, riskScoreRes] = await Promise.all([
      db.threat.count({ where: { status: 'active' } }),
      db.vulnerability.count({ where: { severity: 'critical' } }),
      fetch('/api/risk-score').then(r => r.json()),
    ]);

    const report = await db.report.create({
      data: {
        title: `${type.charAt(0).toUpperCase() + type.slice(1)} Security Report - ${new Date().toLocaleDateString()}`,
        type,
        summary: `Current security status: ${threats} active threats, ${vulnerabilities} critical vulnerabilities, overall risk score: ${riskScoreRes.score}`,
        threatCount: threats,
        vulnerabilityCount: vulnerabilities,
        riskScore: riskScoreRes.score,
        generatedBy: 'System',
      },
    });

    return NextResponse.json({ report });
  } catch (error) {
    console.error('Error generating report:', error);
    return NextResponse.json(
      { error: 'Failed to generate report' },
      { status: 500 }
    );
  }
}
