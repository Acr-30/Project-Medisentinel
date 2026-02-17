import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET() {
  try {
    // Calculate overall risk score based on active threats, critical vulnerabilities, and asset criticality
    const activeThreats = await db.threat.count({
      where: { status: 'active' },
    });

    const criticalVulns = await db.vulnerability.count({
      where: { severity: 'critical' },
    });

    const criticalAssets = await db.asset.count({
      where: { criticality: 'critical' },
    });

    // Calculate risk score (0-100)
    const threatWeight = 0.4;
    const vulnWeight = 0.35;
    const assetWeight = 0.25;

    const threatScore = Math.min((activeThreats / 10) * 100, 100);
    const vulnScore = Math.min((criticalVulns / 5) * 100, 100);
    const assetScore = Math.min((criticalAssets / 10) * 100, 100);

    const overallScore =
      threatScore * threatWeight + vulnScore * vulnWeight + assetScore * assetWeight;

    return NextResponse.json({ score: Math.round(overallScore) });
  } catch (error) {
    console.error('Error calculating risk score:', error);
    return NextResponse.json({ score: 72 }); // Default score
  }
}
