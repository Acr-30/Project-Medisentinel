import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET() {
  try {
    const assets = await db.asset.findMany({
      orderBy: { criticality: 'desc' },
      include: {
        _count: {
          select: {
            threats: true,
            vulnerabilities: true,
            attackLogs: true,
          },
        },
      },
    });

    return NextResponse.json({ assets });
  } catch (error) {
    console.error('Error fetching assets:', error);
    return NextResponse.json(
      { error: 'Failed to fetch assets' },
      { status: 500 }
    );
  }
}
