import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET() {
  try {
    const attackLogs = await db.attackLog.findMany({
      orderBy: { timestamp: 'desc' },
      take: 50,
      include: {
        asset: {
          select: {
            name: true,
            type: true,
          },
        },
        user: {
          select: {
            name: true,
            email: true,
          },
        },
      },
    });

    return NextResponse.json({ attackLogs });
  } catch (error) {
    console.error('Error fetching attack logs:', error);
    return NextResponse.json(
      { error: 'Failed to fetch attack logs' },
      { status: 500 }
    );
  }
}
