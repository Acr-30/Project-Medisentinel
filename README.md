# Medisentinel - Threat Intelligence Framework

**Automated Threat Intelligence Framework to Enhance Cyber Resilience in Private Hospital Sector in Kathmandu Valley**

![Medisentinel Logo](public/medisentinel-shield.svg)

---

## Project Overview

Medisentinel Pvt Ltd is a comprehensive threat intelligence framework designed specifically for healthcare organizations in the Kathmandu Valley. This application provides real-time threat detection, vulnerability management, and automated security monitoring to protect critical hospital infrastructure including EMR systems, lab machines, and patient data.

### Project Objectives

- **Real-time Threat Detection**: Continuous monitoring and automated threat identification
- **Vulnerability Management**: CVE database integration with patch management
- **Risk Assessment**: Automated risk scoring and analysis
- **Incident Response**: Alert system with email/SMS notifications
- **Compliance**: MITRE ATT&CK framework alignment for standardized threat classification
- **Healthcare Focus**: Tailored for hospital IT infrastructure and PHI protection

---

## Core Features

### 1. **Authentication & Access Control**
- Role-based access control (Admin / IT Staff)
- Secure password hashing with bcrypt
- JWT token-based authentication
- Session management

### 2. **Threat Detection & Monitoring**
- Real-time threat feed simulation
- Multiple threat types:
  - Malware attacks (ransomware, trojans, spyware)
  - Phishing campaigns
  - DDoS attacks
  - SQL injection attempts
  - Brute force attacks
  - Cross-site scripting (XSS)
- MITRE ATT&CK framework integration (technique IDs and tactics)
- Geographic IP tracking
- Confidence scoring for threat validation

### 3. **Vulnerability Management**
- CVE database with CVSS scoring
- Exploit status tracking (active, weaponized, PoC, unknown)
- Severity classification (Critical, High, Medium, Low)
- Solution recommendations
- Asset-to-vulnerability mapping

### 4. **Hospital Asset Management**
- Comprehensive asset inventory:
  - EMR/EHR systems
  - Lab information systems
  - Pharmacy databases
  - Radiology PACS servers
  - Workstations and terminals
  - Network devices (firewalls, routers)
- Criticality assessment (Critical, High, Medium, Low)
- Status monitoring (Active, Inactive, Maintenance)
- Location tracking

### 5. **Attack Logs & Incident Tracking**
- Detailed attack timeline
- Network telemetry (Source/Destination IP, Ports, Protocol)
- Attack classification and severity
- Mitigation status tracking
- Forensic information preservation

### 6. **Risk Scoring System**
- Dynamic risk calculation based on:
  - Active threats
  - Critical vulnerabilities
  - Asset criticality
  - Historical attack patterns
- Risk trend analysis (Increasing, Decreasing, Stable)
- Visual risk dashboards

### 7. **Automated Alert System**
- Multi-channel notifications:
  - Dashboard alerts
  - Email notifications
  - SMS alerts
- Severity-based prioritization
- Alert acknowledgment and tracking

### 8. **Mitigation Management**
- Suggested security actions
- Priority-based task management
- Type categorization:
  - Patches
  - Configuration changes
  - Firewall rules
  - Security training
- Due date tracking
- Effort estimation
- Assignment to team members

### 9. **Reporting & Analytics**
- Automated report generation:
  - Daily threat intelligence reports
  - Weekly security summaries
  - Monthly compliance reports
  - Incident-specific reports
- Interactive visualizations:
  - Traffic volume analysis
  - Threat trend charts
  - Vulnerability severity distribution
  - Asset risk scoring
- Export functionality

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Hospital Network Infrastructure               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   EMR    │  │   Lab    │  │ Pharmacy │  │ Radiology│  │
│  │  Server  │  │  System  │  │ Database │  │   PACS   │  │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘  │
│        │            │            │            │            │
│        └────────────┴────────────┴────────────┴────┐       │
│                                                 │       │
│                                          ┌──────▼──────┐│
│                                          │   Core     ││
│                                          │  Firewall  ││
│                                          └──────┬──────┘│
│                                                 │       │
│                                          ┌──────▼──────┐│
│                                          │  Main      ││
│                                          │  Router    ││
│                                          └──────┬──────┘│
└────────────────────────────────────────────────┼──────────┘
                                                 │
                           ┌─────────────────────▼─────────────────────┐
                           │             Log Collector /             │
                           │          Packet Monitor                  │
                           └─────────────────────┬─────────────────────┘
                                                 │
                           ┌─────────────────────▼─────────────────────┐
                           │          Threat Analyzer Engine          │
                           │    • Pattern Recognition                │
                           │    • Anomaly Detection                 │
                           │    • MITRE ATT&CK Classification       │
                           └─────────────────────┬─────────────────────┘
                                                 │
                           ┌─────────────────────▼─────────────────────┐
                           │     Threat Intelligence Database         │
                           │  • Threats • Vulnerabilities • Assets    │
                           │  • Attack Logs • Alerts • Mitigations    │
                           └─────────────────────┬─────────────────────┘
                                                 │
         ┌───────────────────────────────────────┼────────────────────────┐
         │                                       │                        │
┌────────▼────────┐                  ┌────────▼────────┐      ┌─────────▼──────┐
│   Web Dashboard  │                  │  Alert System   │      │   Report       │
│                  │                  │                 │      │   Generator    │
│ • Threat Feed   │◄─────────────────┤ • Email         │      │                │
│ • Vulnerability │   Real-time     │ • SMS          │      │ • Daily        │
│ • Asset Monitor │   Updates       │ • Dashboard     │      │ • Weekly       │
│ • Risk Scores   │                  │                 │      │ • Monthly      │
│ • Attack Logs   │                  └─────────────────┘      └────────────────┘
│ • Mitigations   │
│ • Reports       │
│ • Analytics     │
└─────────────────┘
```

---

## Technology Stack

### Frontend
- **Framework**: Next.js 16 with App Router
- **Language**: TypeScript 5
- **Styling**: Tailwind CSS 4
- **UI Components**: shadcn/ui (Radix UI primitives)
- **Icons**: Lucide React
- **State Management**: React Hooks, Local Storage
- **Charts**: Chart.js with react-chartjs-2

### Backend
- **API**: Next.js API Routes
- **Authentication**: JWT (JSON Web Tokens)
- **Password Hashing**: bcrypt

### Database
- **ORM**: Prisma 6.19.2
- **Database**: SQLite
- **Client**: Prisma Client

### Development Tools
- **Package Manager**: Bun
- **Linting**: ESLint
- **Code Quality**: TypeScript strict mode

---

## Installation & Setup

### Prerequisites

- Node.js 18+ or Bun 1.3+
- Windows 11 / macOS / Linux
- Modern web browser

### Installation Steps

1. **Clone or navigate to project directory**
```bash
cd path/to/medisentinel
```

2. **Install dependencies**
```bash
bun install
```

3. **Set up environment variables**
Create a `.env` file in the root directory:
```env
DATABASE_URL="file:./db/custom.db"
JWT_SECRET="your-secret-key-change-in-production"
```

4. **Initialize database**
```bash
# Set environment variable (Windows PowerShell)
$env:DATABASE_URL = "file:./db/custom.db"

# Push database schema
bunx prisma db push

# Generate Prisma Client
bunx prisma generate

# Seed database with sample data (optional)
bun run prisma/seed.ts
```

5. **Start development server**
```bash
bun run dev
```

6. **Access the application**
```
http://localhost:3000
```

---

## Default Credentials

### Admin Account
- **Email**: `admin@medisentinel.com`
- **Password**: `admin123`
- **Access**: Full system administration

### IT Staff Account
- **Email**: `staff@medisentinel.com`
- **Password**: `staff123`
- **Access**: View and manage threats, vulnerabilities, and alerts

---

## Database Schema

### Core Models

#### **User**
- Authentication and authorization
- Role-based access (admin/staff)
- Activity tracking

#### **Asset**
- Hospital IT infrastructure
- Criticality classification
- Status and location tracking

#### **Threat**
- Detected security threats
- MITRE ATT&CK mapping
- Geographic source tracking
- Confidence scoring

#### **Vulnerability**
- CVE database integration
- CVSS scoring
- Exploit status
- Solution recommendations

#### **Mitigation**
- Security action items
- Priority and status tracking
- Team assignment

#### **AttackLog**
- Incident timeline
- Network telemetry
- Mitigation status

#### **Alert**
- Multi-channel notifications
- Severity-based routing
- Acknowledgment tracking

#### **Report**
- Automated security reports
- Historical compliance data

#### **RiskScore**
- Dynamic risk assessment
- Trend analysis

#### **MitreAttack**
- MITRE ATT&CK framework reference
- Detection and mitigation guidance

---

## User Guide

### Dashboard Overview

The main dashboard provides:
- **Active Threats Count**: Real-time threat monitoring
- **Critical Vulnerabilities**: High-priority CVEs requiring attention
- **Risk Score**: Overall security posture (0-100)
- **Protected Assets**: Total monitored infrastructure

### Navigation Tabs

#### **Overview**
- Recent threats panel
- Alert notifications
- Risk assessment summary

#### **Threats**
- Real-time threat intelligence feed
- Threat details with MITRE ATT&CK mapping
- Source IP geolocation
- Status tracking (Active, Mitigated, Investigating)

#### **Vulnerabilities**
- CVE database search
- CVSS scores and severity
- Exploit status
- Patch recommendations

#### **Assets**
- Hospital asset inventory
- Criticality and status
- Location mapping
- Threat/vulnerability associations

#### **Attack Logs**
- Detailed incident timeline
- Network traffic information
- Protocol and port details
- Mitigation outcomes

#### **Mitigations**
- Recommended security actions
- Priority-based task list
- Status tracking (Pending, In Progress, Completed)
- Team assignments

#### **Analytics**
- Traffic volume charts (24-hour view)
- Threat trend analysis (7-day view)
- Threat type distribution
- Vulnerability severity breakdown
- Asset risk scoring

#### **Reports**
- On-demand report generation
- Daily, Weekly, Monthly reports
- Incident-specific reports
- Download functionality

#### **Alerts**
- Alert history with full details
- Severity-based filtering
- Alert type (Email, SMS, Dashboard)
- Acknowledgment status

---

## Development

### Project Structure

```
medisentinel/
├── prisma/
│   ├── schema.prisma      # Database schema
│   └── seed.ts            # Sample data seeding
├── public/
│   ├── medisentinel-shield.svg  # Main logo
│   ├── favicon-32x32.svg        # Browser icon
│   └── robots.txt               # SEO configuration
├── src/
│   ├── app/
│   │   ├── page.tsx          # Login page
│   │   ├── layout.tsx        # Root layout
│   │   ├── globals.css       # Global styles
│   │   ├── dashboard/
│   │   │   └── page.tsx      # Main dashboard
│   │   └── api/              # API routes
│   │       ├── auth/
│   │       │   └── login/
│   │       │       └── route.ts
│   │       ├── threats/
│   │       │   └── route.ts
│   │       ├── vulnerabilities/
│   │       │   └── route.ts
│   │       ├── assets/
│   │       │   └── route.ts
│   │       ├── alerts/
│   │       │   └── route.ts
│   │       ├── attack-logs/
│   │       │   └── route.ts
│   │       ├── mitigations/
│   │       │   └── route.ts
│   │       ├── reports/
│   │       │   └── route.ts
│   │       ├── risk-score/
│   │       │   └── route.ts
│   │       └── simulate-threat/
│   │           └── route.ts
│   ├── components/
│   │   ├── ui/               # shadcn/ui components
│   │   └── charts/
│   │       └── security-charts.tsx  # Visualization components
│   └── lib/
│       ├── db.ts             # Prisma client
│       └── utils.ts          # Utility functions
├── db/
│   └── custom.db            # SQLite database
├── .env                     # Environment variables
├── package.json             # Dependencies
└── README.md                # This file
```

### Available Scripts

```bash
# Start development server
bun run dev

# Build for production
bun run build

# Start production server
bun run start

# Lint code
bun run lint

# Database operations
bun run db:push          # Push schema to database
bun run db:generate       # Generate Prisma Client
bun run db:reset         # Reset database
```

### Environment Variables

```env
DATABASE_URL="file:./db/custom.db"
JWT_SECRET="your-secret-key-here"
```

---

## Security Features

### Implemented
- ✅ Password hashing with bcrypt
- ✅ JWT token-based authentication
- ✅ Role-based access control
- ✅ SQL injection prevention (Prisma ORM)
- ✅ XSS protection (React default escaping)
- ✅ CSRF protection (Next.js default)
- ✅ Secure password storage
- ✅ Session management

### Best Practices
- Input validation on all forms
- Secure HTTP headers
- Environment variable protection
- Regular dependency updates
- Security-focused code reviews

---

## Performance Optimization

- Next.js 16 App Router for optimal performance
- Static generation where possible
- Database query optimization
- Client-side caching
- Image optimization
- Code splitting
- Lazy loading components

---

## Testing

The application includes:
- Threat simulation (auto-generates new threats every 10 seconds)
- Sample data seeding (users, assets, threats, vulnerabilities, etc.)
- Risk calculation testing
- Alert generation testing

---

## MITRE ATT&CK Integration

The system maps threats to MITRE ATT&CK framework:
- **T1486**: Data Encrypted for Impact (Ransomware)
- **T1566**: Phishing
- **T1190**: Exploit Public-Facing Application
- **T1110**: Brute Force
- **T1498**: Network Denial of Service

Each threat includes:
- Technique ID
- Tactic ID
- Detection guidance
- Mitigation recommendations

---

## Deployment

### Production Considerations

1. **Environment Variables**
   - Change `JWT_SECRET` to a strong, random value
   - Use environment-specific database URLs

2. **Database**
   - Consider PostgreSQL or MySQL for production
   - Set up regular backups
   - Implement database replication

3. **Security**
   - Enable HTTPS
   - Configure CORS properly
   - Implement rate limiting
   - Set up Web Application Firewall (WAF)

4. **Monitoring**
   - Application logging
   - Error tracking (Sentry, etc.)
   - Uptime monitoring
   - Performance monitoring

### Deployment Platforms

- **Vercel** (Recommended for Next.js)
- **AWS** (ECS, Lambda, RDS)
- **Azure** (App Service, SQL Database)
- **Google Cloud** (App Engine, Cloud SQL)
- **Docker** (Containerized deployment)

---

## Contribution

This is a private project for Medisentinel Pvt Ltd. For internal contributions:

1. Follow the existing code style
2. Write TypeScript with strict mode
3. Use ESLint for code quality
4. Test thoroughly before committing
5. Document new features

---

## License

Copyright © 2025 Medisentinel Pvt Ltd. All rights reserved.

Private project - Unauthorized copying, distribution, or modification is strictly prohibited.

---

## Project Vision

Medisentinel aims to revolutionize cybersecurity in the healthcare sector of Kathmandu Valley by providing:
- **Proactive** threat detection and prevention
- **Intelligent** risk assessment and mitigation
- **Automated** incident response and reporting
- **Comprehensive** visibility into security posture
- **Compliance-ready** audit trails and documentation

Together, we're building a more resilient healthcare infrastructure for the digital age. 

---

**Medisentinel - Protecting Healthcare, One Threat at a Time** 💙
