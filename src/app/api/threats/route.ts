import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET() {
  try {
    const threats = await db.threat.findMany({
      orderBy: { createdAt: 'desc' },
      include: {
        asset: {
          select: {
            name: true,
            ipAddress: true,
          },
        },
      },
    });

    return NextResponse.json({ threats });
  } catch (error) {
    console.error('Error fetching threats:', error);
    return NextResponse.json(
      { error: 'Failed to fetch threats' },
      { status: 500 }
    );
  }
}
