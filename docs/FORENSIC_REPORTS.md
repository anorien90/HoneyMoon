# Forensic Reports Feature

## Overview

The Forensic Reports feature provides comprehensive, formal documentation of honeypot incidents suitable for:
- Legal proceedings
- Compliance audits
- Executive briefings
- Security team coordination
- Incident response documentation

## Features

### 1. Enhanced Report Display

Formal forensic reports are displayed with a professional, structured layout including:

- **Header Section**: Session metadata, severity, confidence level
- **Executive Summary**: Highlighted overview of the incident
- **MITRE ATT&CK Mapping**: Visual tags for tactics and techniques
- **8 Comprehensive Sections**:
  1. Executive Summary
  2. Incident Classification
  3. Technical Analysis
  4. Threat Actor Assessment
  5. Indicators of Compromise (IOCs)
  6. Impact Assessment
  7. Recommendations
  8. Evidence Chain

### 2. Reports Management Tab

A dedicated Reports tab provides:
- Generate new reports by session ID
- Browse all generated reports
- Click to view detailed reports
- Export reports as JSON
- Bulk export functionality

### 3. Visual Enhancements

- **Color-coded sections** for easy navigation
- **Severity badges** (Critical/High/Medium/Low)
- **MITRE ATT&CK tags** with appropriate styling
- **IOCs** in highlighted danger zone
- **Recommendations** in success-colored section

## Usage

### Generating a Report

#### From Analysis Tab:
1. Navigate to **Analysis** tab
2. Enter session ID
3. Click **📋 Formal Report** button
4. View the generated report in a modal

#### From Reports Tab:
1. Navigate to **Reports** tab
2. Enter session ID in "Generate New Report" section
3. Click **Generate** button
4. Report appears in the list below

### Viewing Reports

1. Navigate to **Reports** tab
2. Click on any report row in the list
3. Full report displays in a modal with all sections

### Exporting Reports

#### Single Report:
- View report in modal
- Click **💾 Download JSON** to save as JSON file
- Click **📋 Copy to Clipboard** to copy to clipboard

#### Bulk Export:
- Navigate to **Reports** tab
- Click **📦 Export All** to export all reports
- Click **📄 Export Recent (10)** to export 10 most recent reports

## Report Structure

Each formal forensic report includes:

### 1. EXECUTIVE SUMMARY
Brief overview, critical findings, and immediate risk assessment

### 2. INCIDENT CLASSIFICATION
- Incident Type
- Severity Level with justification
- MITRE ATT&CK Framework Mapping

### 3. TECHNICAL ANALYSIS
- Attack Vector Analysis
- Command Sequence Analysis
- Malicious Payload Analysis (if applicable)
- Network Behavior Analysis

### 4. THREAT ACTOR ASSESSMENT
- Skill Level (Script Kiddie/Intermediate/Advanced/APT)
- Automation Assessment
- Attribution Indicators
- Motivation Assessment

### 5. INDICATORS OF COMPROMISE (IOCs)
- Network IOCs (IPs, domains, ports)
- Host IOCs (files, hashes, paths)
- Behavioral IOCs (command patterns, timing)

### 6. IMPACT ASSESSMENT
- Potential Impact if Attack Succeeded
- Data at Risk
- System Integrity Concerns

### 7. RECOMMENDATIONS
- Immediate Actions (within 1 hour)
- Short-term Actions (within 24 hours)
- Long-term Improvements
- Detection Rule Suggestions

### 8. EVIDENCE CHAIN
- List of artifacts preserved
- Evidence integrity notes

## API Integration

The Reports feature uses these existing API endpoints:

```http
# Generate formal report
POST /api/v1/llm/formal_report
Content-Type: application/json
{
  "session_id": 1
}

# List threat analyses (used for reports list)
GET /api/v1/threats?limit=100
```

## Technical Details

### Frontend Components

**Files:**
- `static/reports-ui.js` - Reports tab functionality
- `static/analysis-ui.js` - Enhanced report modal display
- `templates/index.html` - Reports tab and panel HTML

**Panel Configuration:**
```javascript
// In static/ui.js
reports: {
  id: 'panel-reports',
  title: 'Forensic Reports',
  icon: '📋',
  defaultZone: ZONES.LEFT,
  required: false,
  minWidth: 300,
  minHeight: 300,
  sourceSelector: '#reportsCard'
}
```

### Report Data Format

Generated reports follow this JSON structure:

```json
{
  "generated": true,
  "generated_at": "2026-01-03T23:18:34.869906+00:00",
  "session_id": 1,
  "format": "formal_forensic_report",
  "severity": "Medium",
  "confidence": 0.85,
  "summary": "Executive summary text...",
  "mitre_tactics": ["Reconnaissance", "Discovery"],
  "mitre_techniques": ["T1087 (Account Discovery)", "T1083 (File and Directory Discovery)"],
  "iocs": {
    "network_iocs": ["172.26.0.1"],
    "host_iocs": [],
    "behavioral_iocs": ["Command sequence: 'ls', 'ls -a', 'cd /', 'cd ..', 'cd ../home/', 'ls'"]
  },
  "recommended_actions": [
    "Isolate the honeypot system to prevent further unauthorized access",
    "Conduct a thorough review of file permissions and access controls",
    "Implement additional logging for suspicious activities",
    "Enhance user training on cybersecurity best practices"
  ],
  "threat_actor_profile": {
    "skill_level": "Intermediate",
    "automation": "Manual",
    "motivation": "The attacker's motivation is unclear, but this activity suggests preparation for a more targeted attack."
  },
  "report_sections": {
    "1. EXECUTIVE SUMMARY": "...",
    "2. INCIDENT CLASSIFICATION": {...},
    "3. TECHNICAL ANALYSIS": {...},
    "4. THREAT ACTOR ASSESSMENT": {...},
    "5. INDICATORS OF COMPROMISE (IOCs)": {...},
    "6. IMPACT ASSESSMENT": {...},
    "7. RECOMMENDATIONS": {...},
    "8. EVIDENCE CHAIN": {...}
  }
}
```

## Best Practices

1. **Generate reports for significant incidents** - Focus on medium to critical severity sessions
2. **Review before sharing** - Verify accuracy of LLM-generated content
3. **Export regularly** - Keep backups of important reports
4. **Use for documentation** - Include in incident response documentation
5. **Share with stakeholders** - Use for compliance and executive reporting

## Future Enhancements

Potential improvements:
- PDF export functionality
- Report templates customization
- Scheduled report generation
- Email delivery integration
- Report comparison tools
- Historical trend analysis
