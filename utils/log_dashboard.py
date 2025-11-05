#!/usr/bin/env python3
"""
Log Visualization Dashboard
Provides basic visualization and analysis of detection logs
"""
import json
import os
import sys
from datetime import datetime
from collections import Counter
from utils.logging_utils import aggregate_logs

def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def print_section(title):
    """Print a section header"""
    print(f"\n--- {title} ---")

def visualize_logs(log_file_path):
    """Visualize and analyze detection logs"""
    
    if not os.path.exists(log_file_path):
        print(f"ERROR: Log file not found: {log_file_path}")
        return
    
    print_header("Detection Log Analysis Dashboard")
    
    # Aggregate logs
    stats = aggregate_logs(log_file_path)
    
    # Overall Statistics
    print_section("Overall Statistics")
    print(f"Total Detections: {stats['total_detections']}")
    
    if stats['total_detections'] == 0:
        print("\nNo detections found in logs.")
        return
    
    # By Source
    print_section("Detections by Source")
    for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
        percentage = (count / stats['total_detections']) * 100
        bar = "█" * int(percentage / 2)
        print(f"  {source:10} {count:5} ({percentage:5.1f}%) {bar}")
    
    # By Severity
    print_section("Detections by Severity")
    severity_order = ["Critical", "High", "Medium", "Low"]
    for severity in severity_order:
        if severity in stats['by_severity']:
            count = stats['by_severity'][severity]
            percentage = (count / stats['total_detections']) * 100
            bar = "█" * int(percentage / 2)
            print(f"  {severity:10} {count:5} ({percentage:5.1f}%) {bar}")
    
    # Top YARA Rules
    print_section("Top 10 YARA Rules")
    sorted_rules = sorted(stats['by_rule'].items(), key=lambda x: x[1], reverse=True)[:10]
    for i, (rule, count) in enumerate(sorted_rules, 1):
        percentage = (count / stats['total_detections']) * 100
        print(f"  {i:2}. {rule:50} {count:5} ({percentage:5.1f}%)")
    
    # Recent Detections
    print_section("Recent Detections (Last 10)")
    for i, det in enumerate(stats['recent_detections'], 1):
        timestamp = det.get('timestamp', '')[:19] if det.get('timestamp') else 'Unknown'
        source = det.get('source', 'unknown')
        severity = det.get('severity', 'Unknown')
        rules = ', '.join(det.get('yara_match', []))[:50]
        print(f"  {i:2}. [{timestamp}] {severity:8} | {source:6} | {rules}")
    
    # Time-based Analysis (if available)
    print_section("Time-based Analysis")
    try:
        timestamps = []
        with open(log_file_path, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if 'timestamp' in event:
                        ts_str = event['timestamp']
                        # Parse ISO format timestamp
                        if 'T' in ts_str:
                            ts_str = ts_str.split('T')[0]  # Extract date only
                        timestamps.append(ts_str)
                except:
                    continue
        
        if timestamps:
            date_counts = Counter(timestamps)
            print("Detections by Date:")
            for date, count in sorted(date_counts.items(), reverse=True)[:10]:
                print(f"  {date}: {count} detections")
    except Exception as e:
        print(f"  Could not analyze timestamps: {e}")
    
    print("\n" + "=" * 70)
    print("Analysis complete. Use --help for more options.")
    print("=" * 70 + "\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Visualize detection logs")
    parser.add_argument('--log-file', type=str, 
                       default=os.path.join('logs', 'detections.jsonl'),
                       help='Path to detection log file')
    parser.add_argument('--filter-severity', type=str, choices=['Critical', 'High', 'Medium', 'Low'],
                       help='Filter by severity level')
    parser.add_argument('--filter-source', type=str, choices=['memory', 'disk'],
                       help='Filter by source')
    
    args = parser.parse_args()
    
    if args.filter_severity or args.filter_source:
        # Apply filters
        filters = {}
        if args.filter_severity:
            filters['severity'] = args.filter_severity
        if args.filter_source:
            filters['source'] = args.filter_source
        
        stats = aggregate_logs(args.log_file, filters=filters)
        print(f"\nFiltered Results (severity={args.filter_severity}, source={args.filter_source}):")
        print(f"Total Matching Detections: {stats['total_detections']}")
    else:
        visualize_logs(args.log_file)

if __name__ == "__main__":
    main()

