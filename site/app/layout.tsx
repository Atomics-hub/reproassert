import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://atomics-hub.github.io/reproassert/"),
  title: "ReproAssert — The test before the fix",
  description:
    "Turn a public GitHub issue into a verified, repeatable pytest failure inside a strict Docker boundary.",
  alternates: { canonical: "/reproassert/" },
  openGraph: {
    title: "ReproAssert — The test before the fix",
    description:
      "Generate a candidate pytest reproduction, then verify its base failure inside a strict Docker boundary.",
    type: "website",
    url: "/reproassert/",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        {children}
      </body>
    </html>
  );
}
