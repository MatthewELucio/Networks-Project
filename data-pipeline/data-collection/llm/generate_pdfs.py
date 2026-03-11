#!/usr/bin/env python3
"""Generate a set of varied sample PDFs for upload to LLM browser services."""

from __future__ import annotations

import os
import random
from pathlib import Path

from fpdf import FPDF

OUTPUT_DIR = Path(__file__).resolve().parent / "sample_pdfs"

# ---------------------------------------------------------------------------
# Content templates
# ---------------------------------------------------------------------------

REPORT = {
    "title": "Quarterly Performance Report — Q3 2025",
    "sections": [
        ("Executive Summary",
         "This report summarises the key performance indicators for the third quarter of 2025. "
         "Revenue grew by 12% year-over-year, driven primarily by expansion in the APAC region. "
         "Operating expenses remained within budget, though marketing spend increased by 8% to "
         "support new product launches. Customer acquisition cost decreased by 4% compared to Q2."),
        ("Revenue Breakdown",
         "Total revenue: $14.2M\n"
         "  - North America: $6.1M (43%)\n"
         "  - APAC: $4.8M (34%)\n"
         "  - EMEA: $3.3M (23%)\n\n"
         "Subscription revenue accounted for 72% of total revenue, up from 68% in Q2. "
         "One-time service engagements contributed the remaining 28%."),
        ("Key Metrics",
         "Monthly Active Users: 1.23M (+9% QoQ)\n"
         "Churn Rate: 3.1% (down from 3.6%)\n"
         "Net Promoter Score: 62 (up 4 points)\n"
         "Average Revenue Per User: $11.55"),
        ("Outlook",
         "Q4 is expected to benefit from seasonal demand and the launch of the Enterprise tier. "
         "The finance team projects revenue of $15.8–16.4M with a gross margin target of 71%."),
    ],
}

RESEARCH_PAPER = {
    "title": "Effects of Urban Green Spaces on Air Quality: A Meta-Analysis",
    "sections": [
        ("Abstract",
         "Urban green spaces have been proposed as a cost-effective strategy for improving air "
         "quality in metropolitan areas. This meta-analysis synthesises findings from 47 studies "
         "published between 2010 and 2024, covering 23 countries. Results indicate that proximity "
         "to green spaces is associated with a 6–18% reduction in PM2.5 concentrations and a "
         "10–22% reduction in NO2 levels within a 500-meter radius."),
        ("Introduction",
         "Rapid urbanisation has intensified exposure to air pollutants globally. The World Health "
         "Organization estimates that 99% of the global population breathes air exceeding guideline "
         "limits. Trees and vegetation remove pollutants through dry deposition, while also reducing "
         "ambient temperatures via evapotranspiration, indirectly lowering ozone formation."),
        ("Methods",
         "We searched PubMed, Scopus, and Web of Science using the terms 'urban green space', "
         "'air quality', 'PM2.5', and 'NO2'. Studies were included if they reported quantitative "
         "pollution measurements at varying distances from green spaces. Effect sizes were calculated "
         "as standardised mean differences and pooled using a random-effects model."),
        ("Results",
         "The pooled effect size for PM2.5 reduction was −0.42 (95% CI: −0.56 to −0.28, p < 0.001). "
         "For NO2, the pooled effect was −0.58 (95% CI: −0.74 to −0.42, p < 0.001). Larger parks "
         "(>5 ha) showed a stronger effect than smaller green patches. Coniferous trees contributed "
         "more to particle removal but emitted biogenic volatile organic compounds in summer."),
        ("Discussion",
         "These findings support investment in urban forestry programs as a supplementary pollution "
         "mitigation strategy. However, species selection and maintenance regimes should be optimised "
         "to maximise benefits and minimise unintended VOC emissions."),
        ("References",
         "1. Nowak, D.J. et al. (2014). Tree and forest effects on air quality. J. Environ. Manage.\n"
         "2. Escobedo, F.J. et al. (2011). Urban forests and pollution mitigation. Environ. Pollut.\n"
         "3. WHO. (2021). Global Air Quality Guidelines. Geneva.\n"
         "4. Calfapietra, C. et al. (2013). Role of urban trees in air quality. Urban For. Urban Green."),
    ],
}

RESUME = {
    "title": "Jordan A. Taylor — Résumé",
    "sections": [
        ("Contact",
         "Email: jordan.taylor@example.com\n"
         "Phone: (555) 234-5678\n"
         "Location: Portland, OR\n"
         "LinkedIn: linkedin.com/in/jordantaylor"),
        ("Summary",
         "Full-stack software engineer with 6 years of experience building scalable web applications. "
         "Proficient in Python, TypeScript, React, and cloud infrastructure (AWS, GCP). Passionate "
         "about developer tooling, observability, and delivering high-quality user experiences."),
        ("Experience",
         "Senior Software Engineer — Acme Corp (2022–Present)\n"
         "  • Led migration of monolithic Django app to microservices architecture\n"
         "  • Reduced p95 API latency from 1.2s to 180ms\n"
         "  • Mentored 3 junior engineers through structured code review process\n\n"
         "Software Engineer — Beta Inc (2019–2022)\n"
         "  • Built real-time analytics dashboard serving 50k DAU\n"
         "  • Implemented CI/CD pipeline reducing deploy time from 45min to 8min\n"
         "  • Contributed to open-source monitoring library (1.2k GitHub stars)"),
        ("Education",
         "B.S. Computer Science — University of Washington (2019)\n"
         "  GPA: 3.74 | Dean's List 6 semesters"),
        ("Skills",
         "Languages: Python, TypeScript, Go, SQL\n"
         "Frameworks: React, Django, FastAPI, Next.js\n"
         "Infrastructure: AWS (ECS, Lambda, RDS), Docker, Terraform, GitHub Actions"),
    ],
}

MEETING_NOTES = {
    "title": "Product Team Meeting Notes — March 4, 2026",
    "sections": [
        ("Attendees",
         "Sarah Chen (PM), Marcus Johnson (Eng Lead), Priya Patel (Design), "
         "Alex Kowalski (QA), Liam Nguyen (Data)"),
        ("Agenda",
         "1. Sprint retrospective\n"
         "2. Feature flag rollout status\n"
         "3. Mobile redesign timeline\n"
         "4. Q2 OKR alignment"),
        ("Discussion",
         "Sprint 14 retrospective: Team completed 34 of 38 story points. Two tickets "
         "were blocked by third-party API instability (Stripe webhook delays). Action item: "
         "Marcus to add retry logic with exponential backoff.\n\n"
         "Feature flag rollout: Dark mode is at 25% of users. Crash rate unchanged; positive "
         "feedback in NPS comments. Priya recommends full rollout next week.\n\n"
         "Mobile redesign: Figma prototypes are final. Engineering estimates 6 sprints for "
         "full implementation. Alex flagged accessibility concerns with the new nav drawer — "
         "needs screen reader testing before launch."),
        ("Action Items",
         "• Marcus: Implement Stripe webhook retry logic (by 3/11)\n"
         "• Priya: Prepare dark mode full-rollout announcement (by 3/10)\n"
         "• Alex: Schedule accessibility audit with external vendor (by 3/14)\n"
         "• Liam: Pull conversion funnel data for Q2 OKR baseline (by 3/12)"),
    ],
}

PROJECT_PROPOSAL = {
    "title": "Proposal: Campus Bike-Share Expansion Program",
    "sections": [
        ("Overview",
         "This proposal outlines a plan to expand the existing campus bike-share program from "
         "8 stations to 22 stations, increasing fleet size from 120 to 350 bicycles. The expansion "
         "aims to reduce single-occupancy vehicle trips by 15% and improve last-mile connectivity "
         "to public transit stops."),
        ("Background",
         "The current bike-share program, launched in 2023, serves approximately 2,400 unique "
         "riders per month. Survey data indicates that 63% of users cite convenience as their "
         "primary motivation, while 28% ride for environmental reasons. Peak demand consistently "
         "exceeds station capacity at 5 of 8 locations during morning commute hours."),
        ("Budget",
         "Capital costs:\n"
         "  - 14 new docking stations: $280,000\n"
         "  - 230 new bicycles: $184,000\n"
         "  - Installation and site preparation: $95,000\n"
         "  - Technology upgrades (app, GPS): $42,000\n\n"
         "Annual operating costs: $165,000 (maintenance, redistribution, support staff)\n"
         "Total Year 1 cost: $766,000\n"
         "Projected annual revenue (user fees + sponsorship): $310,000"),
        ("Timeline",
         "Phase 1 (Months 1–3): Site selection and permitting\n"
         "Phase 2 (Months 4–6): Station installation and fleet procurement\n"
         "Phase 3 (Month 7): Soft launch with 10 new stations\n"
         "Phase 4 (Month 9): Full launch with remaining 4 stations"),
        ("Conclusion",
         "The expansion addresses documented demand shortfalls and aligns with the university's "
         "2030 carbon neutrality commitment. We recommend approval at the April board meeting to "
         "begin Phase 1 procurement by May."),
    ],
}

TUTORIAL = {
    "title": "Getting Started with SQLite in Python",
    "sections": [
        ("Introduction",
         "SQLite is a lightweight, file-based relational database engine bundled with Python's "
         "standard library. It requires no separate server process and is ideal for prototyping, "
         "small applications, and embedded systems."),
        ("Creating a Database",
         "import sqlite3\n\n"
         "conn = sqlite3.connect('example.db')\n"
         "cursor = conn.cursor()\n\n"
         "cursor.execute('''\n"
         "    CREATE TABLE IF NOT EXISTS users (\n"
         "        id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
         "        name TEXT NOT NULL,\n"
         "        email TEXT UNIQUE NOT NULL,\n"
         "        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n"
         "    )\n"
         "''')\n\n"
         "conn.commit()"),
        ("Inserting Data",
         "cursor.execute(\n"
         "    'INSERT INTO users (name, email) VALUES (?, ?)',\n"
         "    ('Alice', 'alice@example.com')\n"
         ")\n"
         "conn.commit()\n\n"
         "# Insert multiple rows\n"
         "users = [\n"
         "    ('Bob', 'bob@example.com'),\n"
         "    ('Carol', 'carol@example.com'),\n"
         "]\n"
         "cursor.executemany(\n"
         "    'INSERT INTO users (name, email) VALUES (?, ?)', users\n"
         ")\n"
         "conn.commit()"),
        ("Querying Data",
         "cursor.execute('SELECT * FROM users')\n"
         "rows = cursor.fetchall()\n"
         "for row in rows:\n"
         "    print(row)\n\n"
         "# With filtering\n"
         "cursor.execute('SELECT name, email FROM users WHERE id > ?', (1,))\n"
         "print(cursor.fetchall())"),
        ("Best Practices",
         "• Always use parameterised queries to prevent SQL injection.\n"
         "• Use context managers (with conn:) for automatic commit/rollback.\n"
         "• Call conn.close() when finished to release the file lock.\n"
         "• For concurrent access, consider WAL mode: PRAGMA journal_mode=WAL."),
    ],
}

DATA_TABLE_REPORT = {
    "title": "Monthly Sales Data — February 2026",
    "sections": [
        ("Summary",
         "Total units sold: 4,312\n"
         "Total revenue: $287,450\n"
         "Average order value: $66.66\n"
         "Return rate: 3.8%"),
        ("Top Products",
         "Rank  Product                Units   Revenue\n"
         "  1   Wireless Earbuds       812     $48,720\n"
         "  2   USB-C Hub              645     $38,700\n"
         "  3   Mechanical Keyboard    498     $59,760\n"
         "  4   Webcam HD Pro          421     $33,680\n"
         "  5   Laptop Stand           387     $19,350"),
        ("Regional Breakdown",
         "West Coast:   $102,400 (35.6%)\n"
         "East Coast:    $89,200 (31.0%)\n"
         "Midwest:       $54,100 (18.8%)\n"
         "South:         $41,750 (14.5%)"),
        ("Month-over-Month Trend",
         "January 2026:  $261,300 (3,940 units)\n"
         "February 2026: $287,450 (4,312 units)\n"
         "Change: +10.0% revenue, +9.4% units\n\n"
         "The increase is attributed to Presidents' Day promotions and a successful email "
         "campaign that drove 22% higher click-through rates versus the prior month."),
    ],
}

LETTER = {
    "title": "Recommendation Letter for Morgan Rivera",
    "sections": [
        ("To Whom It May Concern",
         "I am writing to recommend Morgan Rivera for admission to your graduate program in "
         "Environmental Engineering. I have known Morgan for three years in my capacity as their "
         "academic advisor and research supervisor at State University."),
        ("Academic Performance",
         "Morgan graduated summa cum laude with a B.S. in Civil Engineering, maintaining a 3.92 "
         "GPA. They consistently outperformed their peers in coursework related to water resources, "
         "fluid mechanics, and environmental chemistry. Their senior thesis on stormwater runoff "
         "modelling received the departmental award for outstanding undergraduate research."),
        ("Research Contributions",
         "As a research assistant in my lab, Morgan developed a novel sensor calibration protocol "
         "that reduced measurement error by 30%. They co-authored two peer-reviewed publications "
         "and presented findings at the ASCE Environmental Conference in 2025. Their work ethic, "
         "intellectual curiosity, and ability to collaborate across disciplines are exceptional."),
        ("Conclusion",
         "Morgan is among the top 5% of students I have mentored in my 18-year academic career. "
         "I give them my highest recommendation without reservation.\n\n"
         "Sincerely,\n"
         "Dr. Patricia Huang\n"
         "Professor of Civil & Environmental Engineering\n"
         "State University"),
    ],
}

TECHNICAL_SPEC = {
    "title": "API Specification: User Authentication Service v2",
    "sections": [
        ("Overview",
         "This document describes the REST API for the User Authentication Service (UAS) v2. "
         "The service handles user registration, login, token refresh, and password reset. "
         "All endpoints require HTTPS and return JSON responses."),
        ("Authentication",
         "POST /api/v2/auth/register\n"
         "  Body: {name, email, password}\n"
         "  Returns: 201 {user_id, email, created_at}\n\n"
         "POST /api/v2/auth/login\n"
         "  Body: {email, password}\n"
         "  Returns: 200 {access_token, refresh_token, expires_in}\n\n"
         "POST /api/v2/auth/refresh\n"
         "  Body: {refresh_token}\n"
         "  Returns: 200 {access_token, expires_in}"),
        ("Token Format",
         "Access tokens are JWTs signed with RS256. Payload includes:\n"
         "  - sub: user_id\n"
         "  - iat: issued-at timestamp\n"
         "  - exp: expiration (15 minutes)\n"
         "  - scope: list of granted permissions\n\n"
         "Refresh tokens are opaque strings stored server-side with a 30-day TTL."),
        ("Error Codes",
         "400 — Malformed request body or missing required fields\n"
         "401 — Invalid credentials or expired token\n"
         "409 — Email already registered\n"
         "422 — Password does not meet complexity requirements\n"
         "429 — Rate limit exceeded (max 10 login attempts per minute per IP)\n"
         "500 — Internal server error"),
        ("Rate Limiting",
         "All endpoints are rate-limited using a sliding window algorithm.\n"
         "Default limits:\n"
         "  - Registration: 5 requests/hour per IP\n"
         "  - Login: 10 requests/minute per IP\n"
         "  - Token refresh: 30 requests/hour per user\n"
         "Clients receive a 429 response with a Retry-After header."),
    ],
}

ESSAY = {
    "title": "The Role of Public Libraries in the Digital Age",
    "sections": [
        ("Introduction",
         "Public libraries have long served as cornerstones of democratic societies, providing "
         "free access to information regardless of socioeconomic status. As digital technologies "
         "reshape how people consume information, libraries face both existential challenges and "
         "unprecedented opportunities to reinvent their role in community life."),
        ("The Digital Divide",
         "Despite widespread internet adoption, the digital divide persists. The Pew Research "
         "Center reports that 7% of U.S. adults lack home broadband access, with the gap widening "
         "among rural, elderly, and low-income populations. Public libraries bridge this divide by "
         "offering free Wi-Fi, computer access, and digital literacy training. During the COVID-19 "
         "pandemic, many libraries expanded hotspot lending programs and parking-lot Wi-Fi to serve "
         "communities locked out of online schooling and telehealth."),
        ("Beyond Books",
         "Modern libraries increasingly function as community hubs. Makerspaces equipped with 3D "
         "printers and laser cutters attract entrepreneurs and hobbyists. Meeting rooms host civic "
         "forums and support groups. Seed libraries, tool-lending programs, and even telescope "
         "checkouts extend the lending model beyond traditional media. These services generate "
         "social capital that is difficult to quantify but essential to community resilience."),
        ("Challenges",
         "Funding remains the primary constraint. Library budgets are often among the first cut "
         "during fiscal downturns, despite high per-dollar returns — the American Library Association "
         "estimates every dollar invested in public libraries yields $4 to $6 in community value. "
         "Additionally, libraries must navigate content moderation debates, cybersecurity "
         "responsibilities, and evolving patron expectations."),
        ("Conclusion",
         "Far from becoming obsolete, public libraries are more relevant than ever. By embracing "
         "technology while preserving their mission of equitable access, they can continue to serve "
         "as vital institutions for learning, connection, and civic engagement."),
    ],
}


ALL_DOCUMENTS = [
    REPORT, RESEARCH_PAPER, RESUME, MEETING_NOTES, PROJECT_PROPOSAL,
    TUTORIAL, DATA_TABLE_REPORT, LETTER, TECHNICAL_SPEC, ESSAY,
]


def _ascii_safe(text: str) -> str:
    """Replace Unicode characters that core PDF fonts cannot render."""
    replacements = {
        "\u2014": "--",   # em dash
        "\u2013": "-",    # en dash
        "\u2018": "'",    # left single quote
        "\u2019": "'",    # right single quote
        "\u201c": '"',    # left double quote
        "\u201d": '"',    # right double quote
        "\u2022": "*",    # bullet
        "\u00e9": "e",    # e-acute (resume)
        "\u2212": "-",    # minus sign
    }
    for char, repl in replacements.items():
        text = text.replace(char, repl)
    # Fallback: drop anything else that latin-1 can't encode
    return text.encode("latin-1", errors="replace").decode("latin-1")


def build_pdf(doc: dict, output_path: Path) -> None:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.multi_cell(0, 10, _ascii_safe(doc["title"]), align="C")
    pdf.ln(6)

    for heading, body in doc["sections"]:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, _ascii_safe(heading), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 5, _ascii_safe(body))
        pdf.ln(4)

    pdf.output(str(output_path))


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for i, doc in enumerate(ALL_DOCUMENTS, 1):
        # Create a filename from the title
        slug = doc["title"].split("—")[0].split(":")[0].strip()
        slug = slug.lower().replace(" ", "_").replace(".", "")
        slug = "".join(c for c in slug if c.isalnum() or c == "_")[:40]
        filename = f"{i:02d}_{slug}.pdf"
        out = OUTPUT_DIR / filename
        build_pdf(doc, out)
        print(f"  Created: {out.name}")

    print(f"\nGenerated {len(ALL_DOCUMENTS)} PDFs in {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
