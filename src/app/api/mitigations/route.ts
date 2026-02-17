import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET() {
  try {
    const mitigations = await db.mitigation.findMany({
      orderBy: { priority: 'desc' },
      include: {
        threat: {
          select: {
            name: true,
            severity: true,
          },
        },
        vulnerability: {
          select: {
            cveId: true,
            title: true,
            severity: true,
          },
        },
        assignedToUser: {
          select: {
            name: true,
            email: true,
          },
        },
      },
    });

    return NextResponse.json({ mitigations });
  } catch (error) {
    console.error('Error fetching mitigations:', error);
    return NextResponse.json(
      { error: 'Failed to fetch mitigations' },
      { status: 500 }
    );
  }
}
