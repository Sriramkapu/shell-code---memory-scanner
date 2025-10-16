import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import yaml
import os
import traceback
import json
from datetime import datetime, timezone
import pytz
import platform
import socket

def load_email_config():
    config_path = os.path.join(os.path.dirname(__file__), '../config/agent_config.yaml')
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config.get('email', {})

def convert_utc_to_local(utc_timestamp_str):
    """Convert UTC timestamp string to local timezone"""
    try:
        # Parse the UTC timestamp
        utc_dt = datetime.fromisoformat(utc_timestamp_str.replace('Z', '+00:00'))
        
        # Get local timezone (you can specify a specific timezone if needed)
        # For example: local_tz = pytz.timezone('Asia/Kolkata') for IST
        local_tz = datetime.now().astimezone().tzinfo
        
        # Convert to local time
        local_dt = utc_dt.astimezone(local_tz)
        
        # Format for display
        return local_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    except Exception as e:
        print(f"Error converting timestamp: {e}")
        return utc_timestamp_str

def format_detection_event_for_email(event):
    """Format detection event with local timezone for email"""
    formatted_event = event.copy()
    
    # Convert timestamp to local timezone
    if 'timestamp' in formatted_event:
        formatted_event['timestamp'] = convert_utc_to_local(formatted_event['timestamp'])
    
    return formatted_event

def get_severity_color(severity):
    """Get color for severity level"""
    colors = {
        'High': '#dc3545',      # Red
        'Medium': '#ffc107',    # Yellow
        'Low': '#28a745',       # Green
        'Critical': '#721c24'   # Dark Red
    }
    return colors.get(severity, '#6c757d')  # Gray default

def get_severity_icon(severity):
    """Get icon for severity level"""
    icons = {
        'High': '🔴',
        'Medium': '🟡', 
        'Low': '🟢',
        'Critical': '🚨'
    }
    return icons.get(severity, '⚪')

def generate_html_email_body(event):
    """Generate rich HTML email body for detection event"""
    source = event.get('source', 'unknown')
    severity = event.get('severity', 'Unknown')
    yara_matches = event.get('yara_match', [])
    timestamp = convert_utc_to_local(event.get('timestamp', ''))
    host = event.get('host', 'Unknown')
    
    # Get system information
    system_info = f"{platform.system()} {platform.release()}"
    hostname = socket.gethostname()
    
    # Severity styling
    severity_color = get_severity_color(severity)
    severity_icon = get_severity_icon(severity)
    
    # Action styling
    action = event.get('action', 'Unknown')
    action_style = 'color: #dc3545; font-weight: bold;' if 'Blocked' in action else 'color: #28a745;'
    
    # YARA matches styling and detailed blocks
    yara_html = ''
    details = event.get('yara_details', [])
    if details:
        for d in details:
            rule = d.get('rule', 'Unknown')
            meta = d.get('meta', {})
            desc = meta.get('description', '')
            category = meta.get('category', '')
            severity_tag = meta.get('severity', severity)
            strings = d.get('strings', [])
            strings_table_rows = ''
            for s in strings:
                if isinstance(s, dict):
                    sid = s.get('id','')
                    soff = s.get('offset','')
                    slen = s.get('length','')
                    sasc = s.get('ascii','')
                    shex = s.get('hex','')
                else:
                    # Fallback when strings are provided as simple identifiers
                    sid = str(s)
                    soff = ''
                    slen = ''
                    sasc = ''
                    shex = ''
                strings_table_rows += (
                    f"<tr><td style='font-family: monospace'>{sid}</td>"
                    f"<td style='font-family: monospace'>{soff}</td>"
                    f"<td style='font-family: monospace'>{slen}</td>"
                    f"<td style='font-family: monospace'>{sasc}</td>"
                    f"<td style='font-family: monospace'>{shex}</td></tr>"
                )
            if not strings_table_rows:
                strings_table_rows = "<tr><td colspan='5' style='font-style: italic; color: #666;'>No string captures available</td></tr>"

            yara_html += f"""
            <div style="background: #fff; border: 1px solid #e9ecef; border-left: 4px solid #1976d2; padding: 12px; margin: 10px 0; border-radius: 6px;">
                <div style="display:flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-weight: bold; font-family: monospace;">Rule: {rule}</div>
                        <div style="font-size: 12px; color: #555;">{desc}</div>
                        <div style="font-size: 12px; color: #777;">Category: {category}</div>
                    </div>
                    <div>
                        <span class="severity-badge" style="background-color: {get_severity_color(severity_tag)}; color: white;">{severity_tag}</span>
                    </div>
                </div>
                <div style="margin-top:10px;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead>
                            <tr style="background:#f1f3f5; text-align:left;">
                                <th style="padding:6px; font-size:12px;">ID</th>
                                <th style="padding:6px; font-size:12px;">Offset</th>
                                <th style="padding:6px; font-size:12px;">Length</th>
                                <th style="padding:6px; font-size:12px;">ASCII</th>
                                <th style="padding:6px; font-size:12px;">Hex</th>
                            </tr>
                        </thead>
                        <tbody>
                            {strings_table_rows}
                        </tbody>
                    </table>
                </div>
                <div style="font-size: 12px; color:#555; margin-top:8px;">
                    Recommended Action: Investigate process/file, isolate if untrusted, and triage indicators.
                </div>
            </div>
            """
    else:
        for match in yara_matches:
            yara_html += f'<span style="background-color: #f8f9fa; padding: 2px 6px; border-radius: 3px; margin: 2px; display: inline-block; font-family: monospace;">{match}</span>'
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f8f9fa;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 20px;
                text-align: center;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            .alert-banner {{
                background-color: {severity_color};
                color: white;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 20px;
                text-align: center;
                font-size: 18px;
                font-weight: bold;
                box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            }}
            .info-card {{
                background: white;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                border-left: 4px solid {severity_color};
            }}
            .info-grid {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 15px;
                margin-bottom: 20px;
            }}
            .info-item {{
                background: #f8f9fa;
                padding: 12px;
                border-radius: 6px;
                border: 1px solid #e9ecef;
            }}
            .info-label {{
                font-weight: bold;
                color: #495057;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .info-value {{
                font-size: 14px;
                margin-top: 4px;
                word-break: break-word;
            }}
            .yara-section {{
                background: #e3f2fd;
                padding: 15px;
                border-radius: 6px;
                margin-bottom: 20px;
            }}
            .system-info {{
                background: #f5f5f5;
                padding: 15px;
                border-radius: 6px;
                font-size: 12px;
                color: #666;
                border-top: 1px solid #ddd;
                margin-top: 20px;
            }}
            .footer {{
                text-align: center;
                margin-top: 30px;
                padding: 20px;
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .severity-badge {{
                display: inline-block;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: bold;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .action-badge {{
                display: inline-block;
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: bold;
                text-transform: uppercase;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1 style="margin: 0; font-size: 28px;">🛡️ Memory Shellcode Detection</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">Enterprise Security Alert System</p>
        </div>
        
        <div class="alert-banner">
            {severity_icon} SECURITY ALERT DETECTED {severity_icon}
        </div>
        
        <div class="info-card">
            <h2 style="margin-top: 0; color: {severity_color};">
                {severity_icon} Detection Summary
            </h2>
            
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Detection Source</div>
                    <div class="info-value">{source.title()}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Severity Level</div>
                    <div class="info-value">
                        <span class="severity-badge" style="background-color: {severity_color}; color: white;">
                            {severity}
                        </span>
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">Detection Time</div>
                    <div class="info-value">{timestamp}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Action Taken</div>
                    <div class="info-value">
                        <span class="action-badge" style="{action_style}">
                            {action}
                        </span>
                    </div>
                </div>
            </div>
            
            <div class="yara-section">
                <h3 style="margin-top: 0; color: #1976d2;">🔍 YARA Pattern Matches</h3>
                <div style="margin-top: 10px;">
                    {yara_html}
                </div>
            </div>
            
            <h3 style="color: #495057;">📋 Detailed Information</h3>
            <div class="info-grid">
    """
    
    # Add specific details based on source
    if source == 'memory':
        process = event.get('process', 'Unknown')
        pid = event.get('pid', 'Unknown')
        memory_hash = event.get('memory_region_hash', 'Unknown')
        
        html_body += f"""
                <div class="info-item">
                    <div class="info-label">Process Name</div>
                    <div class="info-value">{process}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Process ID</div>
                    <div class="info-value">{pid}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Memory Region Hash</div>
                    <div class="info-value" style="font-family: monospace; font-size: 12px;">{memory_hash}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Dump File</div>
                    <div class="info-value" style="font-family: monospace; font-size: 12px;">{event.get('dump_path', 'N/A')}</div>
                </div>
        """
    elif source == 'disk':
        file_path = event.get('file_path', 'Unknown')
        html_body += f"""
                <div class="info-item">
                    <div class="info-label">File Path</div>
                    <div class="info-value" style="font-family: monospace; font-size: 12px;">{file_path}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">File Entropy (sample)</div>
                    <div class="info-value">{event.get('file_entropy','N/A')}</div>
                </div>
        """
    
    html_body += f"""
            </div>
        </div>
        
        <div class="system-info">
            <strong>System Information:</strong><br>
            Host: {hostname} | OS: {system_info} | Detection Host: {host}
        </div>
        
        <div class="footer">
            <p style="margin: 0; color: #666;">
                This alert was automatically generated by the Memory Shellcode Detection Framework.<br>
                For immediate response, contact your security team.
            </p>
            <p style="margin: 10px 0 0 0; font-size: 12px; color: #999;">
                Generated at {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}
            </p>
        </div>
    </body>
    </html>
    """
    
    return html_body

def generate_text_email_body(event):
    """Generate plain text email body for fallback"""
    source = event.get('source', 'unknown')
    severity = event.get('severity', 'Unknown')
    yara_matches = event.get('yara_match', [])
    timestamp = convert_utc_to_local(event.get('timestamp', ''))
    
    text_body = f"""
SECURITY ALERT - Memory Shellcode Detection Framework
{'='*60}

DETECTION SUMMARY:
- Source: {source.title()}
- Severity: {severity}
- Time: {timestamp}
- Action: {event.get('action', 'Unknown')}

YARA PATTERN MATCHES:
{', '.join(yara_matches)}

DETAILED INFORMATION:
"""
    
    if source == 'memory':
        text_body += f"""
- Process: {event.get('process', 'Unknown')}
- PID: {event.get('pid', 'Unknown')}
- Memory Hash: {event.get('memory_region_hash', 'Unknown')}
- Dump File: {event.get('dump_path', 'N/A')}
"""
    elif source == 'disk':
        text_body += f"""
- File Path: {event.get('file_path', 'Unknown')}
"""
    
    text_body += f"""

System: {platform.system()} {platform.release()}
Host: {socket.gethostname()}
Detection Host: {event.get('host', 'Unknown')}

Generated at: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}
"""
    
    return text_body

def send_email_notification(subject, body, html_body=None):
    email_cfg = load_email_config()
    smtp_server = email_cfg.get('smtp_server')
    smtp_port = email_cfg.get('smtp_port', 587)
    smtp_user = email_cfg.get('smtp_user')
    smtp_password = email_cfg.get('smtp_password')
    recipients = email_cfg.get('recipients', [])
    if not (smtp_server and smtp_user and smtp_password and recipients):
        print('Email config incomplete, cannot send notification.')
        return
    
    # Create multipart message for HTML and text
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = ', '.join(recipients)
    
    # Add text part
    text_part = MIMEText(body, 'plain', 'utf-8')
    msg.attach(text_part)
    
    # Add HTML part if provided
    if html_body:
        html_part = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(html_part)
    
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, recipients, msg.as_string())
        print('Email notification sent!')
    except Exception as e:
        print('Failed to send email notification:', e)
        traceback.print_exc()

def send_detection_email_notification(event):
    """Send email notification for detection event with proper timezone formatting and rich HTML"""
    # Format the event with local timezone
    formatted_event = format_detection_event_for_email(event)
    
    # Create subject with emoji and severity
    source = event.get('source', 'unknown')
    severity = event.get('severity', 'Unknown')
    yara_matches = event.get('yara_match', [])
    severity_icon = get_severity_icon(severity)
    
    subject = f"{severity_icon} SECURITY ALERT ({source.title()}): {', '.join(yara_matches)}"
    
    # Generate both HTML and text versions
    html_body = generate_html_email_body(event)
    text_body = generate_text_email_body(event)
    
    # Send the notification with both HTML and text
    send_email_notification(subject, text_body, html_body) 