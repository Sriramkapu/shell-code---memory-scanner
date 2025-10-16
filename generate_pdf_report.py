#!/usr/bin/env python3
"""
PDF Report Generator for Memory Shellcode Detection
Generates comprehensive PDF reports from detection logs
"""

import os
import json
import yaml
from datetime import datetime, timezone
import pytz
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

class PDFReportGenerator:
    def __init__(self, config_path='config/agent_config.yaml'):
        """Initialize PDF report generator"""
        self.config_path = config_path
        self.report_dir = 'reports'
        self.log_path = 'logs/detections.jsonl'
        
        # Ensure report directory exists
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Load configuration
        try:
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
            self.config = {}
    
    def convert_utc_to_local(self, utc_timestamp_str):
        """Convert UTC timestamp string to local timezone for display"""
        try:
            # Parse the UTC timestamp
            utc_dt = datetime.fromisoformat(utc_timestamp_str.replace('Z', '+00:00'))
            
            # Get local timezone
            local_tz = datetime.now().astimezone().tzinfo
            
            # Convert to local time
            local_dt = utc_dt.astimezone(local_tz)
            
            # Format for display
            return local_dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            print(f"Error converting timestamp: {e}")
            return utc_timestamp_str[:19]  # Return just the date/time part without timezone
    
    def load_detection_events(self):
        """Load detection events from log file"""
        events = []
        
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, 'r') as f:
                    for line in f:
                        if line.strip():
                            events.append(json.loads(line))
                print(f"Loaded {len(events)} detection events")
            except Exception as e:
                print(f"Error loading events: {e}")
        else:
            print(f"Log file not found: {self.log_path}")
        
        return events
    
    def generate_comprehensive_report(self, output_path=None):
        """Generate comprehensive PDF report"""
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.report_dir, f"comprehensive_detection_report_{timestamp}.pdf")
        
        try:
            # Load events
            events = self.load_detection_events()
            
            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=20,
                spaceAfter=30,
                alignment=1,  # Center
                textColor=colors.darkblue
            )
            
            subtitle_style = ParagraphStyle(
                'CustomSubtitle',
                parent=styles['Heading2'],
                fontSize=14,
                spaceAfter=20,
                textColor=colors.darkred
            )
            
            # Title page
            story.append(Paragraph("Memory Shellcode Detection Framework", title_style))
            story.append(Spacer(1, 20))
            story.append(Paragraph("Comprehensive Security Report", subtitle_style))
            story.append(Spacer(1, 30))
            
            # Report metadata
            story.append(Paragraph(f"Generated: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}", styles['Normal']))
            story.append(Paragraph(f"Total Detections: {len(events)}", styles['Normal']))
            story.append(Paragraph(f"Report Period: {self._get_report_period(events)}", styles['Normal']))
            story.append(PageBreak())
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading1']))
            story.append(Spacer(1, 12))
            
            summary_stats = self._generate_summary_stats(events)
            story.append(Paragraph(summary_stats, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Detection Details
            if events:
                story.append(Paragraph("Detection Details", styles['Heading1']))
                story.append(Spacer(1, 12))
                
                # Create detailed table
                headers = ['Timestamp', 'Source', 'Process/File', 'YARA Match', 'Severity', 'Action']
                table_data = [headers]
                
                for event in events:
                    table_data.append([
                        self.convert_utc_to_local(event.get('timestamp', '')),
                        event.get('source', ''),
                        self._truncate_text(event.get('process', event.get('file_path', '')), 25),
                        self._truncate_text(', '.join(event.get('yara_match', [])), 25),
                        event.get('severity', ''),
                        event.get('action', '')
                    ])
                
                # Create table with better styling
                detection_table = Table(table_data, colWidths=[1.3*inch, 0.8*inch, 1.8*inch, 1.5*inch, 0.8*inch, 1.2*inch])
                detection_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
                ]))
                story.append(detection_table)
                story.append(PageBreak())
            
            # Threat Analysis
            story.append(Paragraph("Threat Analysis", styles['Heading1']))
            story.append(Spacer(1, 12))
            
            threat_analysis = self._generate_threat_analysis(events)
            story.append(Paragraph(threat_analysis, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Recommendations
            story.append(Paragraph("Security Recommendations", styles['Heading1']))
            story.append(Spacer(1, 12))
            
            recommendations = self._generate_recommendations(events)
            story.append(Paragraph(recommendations, styles['Normal']))
            
            # Build PDF
            doc.build(story)
            print(f"✅ Comprehensive PDF report generated: {output_path}")
            return output_path
            
        except ImportError:
            print("❌ ReportLab not installed. Install with: pip install reportlab")
            return None
        except Exception as e:
            print(f"❌ Error generating PDF report: {e}")
            return None
    
    def _get_report_period(self, events):
        """Get report period from events"""
        if not events:
            return "No events"
        
        timestamps = [event.get('timestamp', '') for event in events if event.get('timestamp')]
        if timestamps:
            start = min(timestamps)[:10]  # Date only
            end = max(timestamps)[:10]
            return f"{start} to {end}"
        return "Unknown"
    
    def _generate_summary_stats(self, events):
        """Generate summary statistics"""
        if not events:
            return "No detection events found."
        
        # Count by source
        memory_events = [e for e in events if e.get('source') == 'memory']
        disk_events = [e for e in events if e.get('source') == 'disk']
        
        # Count by severity
        high_severity = [e for e in events if e.get('severity') == 'High']
        medium_severity = [e for e in events if e.get('severity') == 'Medium']
        low_severity = [e for e in events if e.get('severity') == 'Low']
        
        # Count by YARA match
        yara_matches = {}
        for event in events:
            for match in event.get('yara_match', []):
                yara_matches[match] = yara_matches.get(match, 0) + 1
        
        summary = f"""
        <b>Detection Summary:</b><br/>
        • Total Detections: {len(events)}<br/>
        • Memory-based: {len(memory_events)}<br/>
        • Disk-based: {len(disk_events)}<br/>
        • High Severity: {len(high_severity)}<br/>
        • Medium Severity: {len(medium_severity)}<br/>
        • Low Severity: {len(low_severity)}<br/>
        <br/>
        <b>Top YARA Matches:</b><br/>
        """
        
        for match, count in sorted(yara_matches.items(), key=lambda x: x[1], reverse=True)[:5]:
            summary += f"• {match}: {count} detections<br/>"
        
        return summary
    
    def _generate_threat_analysis(self, events):
        """Generate threat analysis"""
        if not events:
            return "No threats detected."
        
        analysis = """
        <b>Threat Analysis:</b><br/>
        """
        
        # Analyze patterns
        memory_threats = [e for e in events if e.get('source') == 'memory']
        disk_threats = [e for e in events if e.get('source') == 'disk']
        
        if memory_threats:
            analysis += f"<br/><b>Memory-based Threats ({len(memory_threats)}):</b><br/>"
            analysis += "• Suspicious shellcode patterns detected in process memory<br/>"
            analysis += "• Potential code injection or process manipulation<br/>"
            analysis += "• Immediate action required to prevent execution<br/>"
        
        if disk_threats:
            analysis += f"<br/><b>Disk-based Threats ({len(disk_threats)}):</b><br/>"
            analysis += "• Malicious files detected on disk<br/>"
            analysis += "• Potential malware or suspicious executables<br/>"
            analysis += "• Quarantine and analysis recommended<br/>"
        
        return analysis
    
    def _generate_recommendations(self, events):
        """Generate security recommendations"""
        if not events:
            return "No specific recommendations due to lack of detection events."
        
        recommendations = """
        <b>Security Recommendations:</b><br/>
        <br/>
        <b>Immediate Actions:</b><br/>
        • Review all detected processes and files<br/>
        • Quarantine suspicious files immediately<br/>
        • Analyze memory dumps for additional threats<br/>
        • Update YARA rules based on new patterns<br/>
        <br/>
        <b>Long-term Measures:</b><br/>
        • Implement continuous monitoring<br/>
        • Regular security audits and assessments<br/>
        • Employee security awareness training<br/>
        • Network segmentation and access controls<br/>
        <br/>
        <b>System Hardening:</b><br/>
        • Enable DEP (Data Execution Prevention)<br/>
        • Configure ASLR (Address Space Layout Randomization)<br/>
        • Implement application whitelisting<br/>
        • Regular system updates and patches<br/>
        """
        
        return recommendations
    
    def _truncate_text(self, text, max_length):
        """Truncate text to specified length"""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."

def main():
    """Main function to generate PDF report"""
    print("📊 PDF Report Generator for Memory Shellcode Detection")
    print("=" * 60)
    
    # Initialize generator
    generator = PDFReportGenerator()
    
    # Generate comprehensive report
    report_path = generator.generate_comprehensive_report()
    
    if report_path:
        print(f"\n✅ Report generated successfully!")
        print(f"📄 Location: {report_path}")
        print(f"📁 Directory: {os.path.dirname(report_path)}")
        
        # Show how to access
        print(f"\n🔍 How to access your PDF report:")
        print(f"1. File Explorer: Navigate to {os.path.abspath('reports')}")
        print(f"2. Command Line: start {report_path}")
        print(f"3. Direct Path: {os.path.abspath(report_path)}")
        
        # Try to open the report
        try:
            import subprocess
            subprocess.run(['start', report_path], shell=True)
            print(f"\n🚀 Opening PDF report...")
        except Exception as e:
            print(f"Could not auto-open: {e}")
    else:
        print("❌ Failed to generate PDF report")

if __name__ == "__main__":
    main()
