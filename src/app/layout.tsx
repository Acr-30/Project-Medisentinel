import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Medisentinel - Threat Intelligence",
  description: "Automated Threat Intelligence Framework for Healthcare Cyber Resilience in Private Hospital Sector in Kathmandu Valley",
  keywords: ["Medisentinel", "Threat Intelligence", "Cybersecurity", "Healthcare Security", "Hospital Security", "Cyber Resilience", "Vulnerability Management", "Attack Detection"],
  authors: [{ name: "Medisentinel Team" }],
  icons: {
    icon: "/favicon-32x32.svg",
  },
  openGraph: {
    title: "Medisentinel - Threat Intelligence",
    description: "Automated Threat Intelligence Framework for Healthcare Cyber Resilience in Private Hospital Sector in Kathmandu Valley",
    url: "https://medisentinel.com",
    siteName: "Medisentinel",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Medisentinel - Threat Intelligence",
    description: "Automated Threat Intelligence Framework for Healthcare Cyber Resilience",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}