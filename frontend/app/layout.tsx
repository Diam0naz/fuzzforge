import type { Metadata } from "next";
import { Archivo, IBM_Plex_Mono } from "next/font/google";
import Link from "next/link";

import { CONTACT_EMAIL } from "@/lib/api";
import "./globals.css";

const archivo = Archivo({
  subsets: ["latin"],
  axes: ["wdth"],
  variable: "--font-archivo",
  display: "swap",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Fuzzforge: pre-audit fuzzing for Solana programs",
  description:
    "Hostile Token-2022 mints, protocol invariants and replayable failing cases for Anchor programs heading to audit.",
  robots: { index: false, follow: false },
  other: { referrer: "no-referrer" },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={archivo.variable}
      // Set directly: the generated class for a second variable font can
      // disagree between the prerendered HTML and the CSS chunk.
      style={{ "--font-mono": plexMono.style.fontFamily } as React.CSSProperties}
    >
      <body>
        <a className="skip-link" href="#main">
          Skip to content
        </a>
        <header className="site-header">
          <div className="wrap site-header-inner">
            <Link href="/" className="wordmark">
              Fuzzforge
            </Link>
            <nav className="site-nav" aria-label="Main">
              <a href="/#method">Method</a>
              <a href="/#findings">Sample findings</a>
              <a href="/#engagements">Engagements</a>
              <a className="btn btn-primary btn-small" href={`mailto:${CONTACT_EMAIL}`}>
                Request an engagement
              </a>
            </nav>
          </div>
        </header>
        <div id="main">{children}</div>
        <footer className="site-footer">
          <div className="wrap site-footer-inner">
            <p className="wordmark wordmark-small">Fuzzforge</p>
            <p>Pre-audit fuzzing for Solana programs. Not a substitute for a manual audit.</p>
            <p>
              <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
