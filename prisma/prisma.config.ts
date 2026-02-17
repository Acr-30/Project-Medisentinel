import { PrismaClient } from '@prisma/client';
import dotenv from 'dotenv';

dotenv.config(); // loads DATABASE_URL from .env

export const prisma = new PrismaClient({
  datasources: {
    db: process.env.DATABASE_URL, // must match your SQLite file
  },
});
