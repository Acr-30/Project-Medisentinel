import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET() {
  try {
    const vulnerabilities = await db.vulnerability.findMany({
      orderBy: { cvssScore: 'desc' },
      include: {
        asset: {
          select: {
            name: true,
            type: true,
          },
        },
      },
    });

    return NextResponse.json({ vulnerabilities });
  } catch (error) {
    console.error('Error fetching vulnerabilities:', error);
    return NextResponse.json(
      { error: 'Failed to fetch vulnerabilities' },
      { status: 500 }
    );
  }
}
