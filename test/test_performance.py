"""
Performance and Stress Tests
Tests system behavior under load with large datasets and process counts
"""
import unittest
import os
import sys
import tempfile
import time
import json
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.logging_utils import RotatingJSONLogger, aggregate_logs
from utils.security_utils import compute_sha256


class TestPerformance(unittest.TestCase):
    """Performance and stress tests"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, 'test_detections.jsonl')
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_large_log_aggregation(self):
        """Test log aggregation with large number of entries"""
        print("\n[TEST] Large log aggregation (10,000 entries)...")
        
        # Generate large log file
        start_time = time.time()
        with open(self.log_file, 'w') as f:
            for i in range(10000):
                event = {
                    "timestamp": "2025-01-01T00:00:00+00:00",
                    "source": "memory" if i % 2 == 0 else "disk",
                    "severity": ["Critical", "High", "Medium", "Low"][i % 4],
                    "yara_match": [f"Rule_{i % 100}"],
                    "pid": i % 1000
                }
                f.write(json.dumps(event) + '\n')
        
        # Aggregate logs
        stats = aggregate_logs(self.log_file)
        elapsed = time.time() - start_time
        
        self.assertEqual(stats['total_detections'], 10000)
        self.assertGreater(stats['by_source']['memory'], 0)
        self.assertGreater(stats['by_source']['disk'], 0)
        
        print(f"  ✓ Processed 10,000 entries in {elapsed:.2f} seconds")
        print(f"  ✓ Memory detections: {stats['by_source'].get('memory', 0)}")
        print(f"  ✓ Disk detections: {stats['by_source'].get('disk', 0)}")
        self.assertLess(elapsed, 5.0, "Log aggregation should complete in < 5 seconds")
    
    def test_rotating_logger_performance(self):
        """Test rotating logger performance"""
        print("\n[TEST] Rotating logger performance (1,000 entries)...")
        
        logger = RotatingJSONLogger(self.log_file, max_bytes=1024*1024, backup_count=5)
        
        start_time = time.time()
        for i in range(1000):
            event = {
                "timestamp": "2025-01-01T00:00:00+00:00",
                "source": "memory",
                "severity": "High",
                "yara_match": [f"Rule_{i}"],
                "pid": i
            }
            logger.log_detection(event)
        
        elapsed = time.time() - start_time
        
        # Verify log file exists
        self.assertTrue(os.path.exists(self.log_file))
        
        # Count lines
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
        
        self.assertEqual(len(lines), 1000)
        print(f"  ✓ Logged 1,000 entries in {elapsed:.2f} seconds")
        print(f"  ✓ Average: {elapsed/1000*1000:.2f} ms per entry")
        self.assertLess(elapsed, 2.0, "Logging should complete in < 2 seconds")
    
    def test_sha256_computation_performance(self):
        """Test SHA256 computation performance on large files"""
        print("\n[TEST] SHA256 computation performance...")
        
        # Create large test file (1MB)
        test_file = os.path.join(self.temp_dir, 'large_file.bin')
        with open(test_file, 'wb') as f:
            f.write(b'0' * 1024 * 1024)  # 1MB
        
        start_time = time.time()
        hash_value = compute_sha256(test_file)
        elapsed = time.time() - start_time
        
        self.assertIsNotNone(hash_value)
        self.assertEqual(len(hash_value), 64)  # SHA256 produces 64-char hex string
        print(f"  ✓ Computed SHA256 for 1MB file in {elapsed:.2f} seconds")
        print(f"  ✓ Hash: {hash_value[:16]}...")
        self.assertLess(elapsed, 1.0, "SHA256 computation should complete in < 1 second")
    
    def test_many_process_scan_simulation(self):
        """Simulate scanning many processes"""
        print("\n[TEST] Many process scan simulation...")
        
        # Simulate scanning 100 processes
        num_processes = 100
        start_time = time.time()
        
        events = []
        for i in range(num_processes):
            # Simulate detection event creation
            event = {
                "timestamp": "2025-01-01T00:00:00+00:00",
                "source": "memory",
                "process": f"test_process_{i}",
                "pid": 1000 + i,
                "yara_match": ["Test_Rule"],
                "severity": "Medium"
            }
            events.append(event)
        
        # Simulate log writing
        logger = RotatingJSONLogger(self.log_file)
        for event in events:
            logger.log_detection(event)
        
        elapsed = time.time() - start_time
        
        print(f"  ✓ Simulated scan of {num_processes} processes in {elapsed:.2f} seconds")
        print(f"  ✓ Average: {elapsed/num_processes*1000:.2f} ms per process")
        self.assertLess(elapsed, 5.0, "Process scan simulation should complete in < 5 seconds")
    
    def test_concurrent_log_writes(self):
        """Test concurrent log writes (simulated)"""
        print("\n[TEST] Concurrent log writes (simulated)...")
        
        logger = RotatingJSONLogger(self.log_file)
        
        # Simulate concurrent writes
        start_time = time.time()
        num_threads = 10
        events_per_thread = 100
        
        for thread_id in range(num_threads):
            for i in range(events_per_thread):
                event = {
                    "timestamp": "2025-01-01T00:00:00+00:00",
                    "source": "memory",
                    "severity": "High",
                    "yara_match": [f"Rule_{thread_id}_{i}"],
                    "pid": thread_id * 1000 + i,
                    "thread_id": thread_id
                }
                logger.log_detection(event)
        
        elapsed = time.time() - start_time
        
        # Verify all entries were written
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
        
        self.assertEqual(len(lines), num_threads * events_per_thread)
        print(f"  ✓ Wrote {num_threads * events_per_thread} entries in {elapsed:.2f} seconds")
        print(f"  ✓ Throughput: {num_threads * events_per_thread / elapsed:.0f} entries/second")
        self.assertLess(elapsed, 10.0, "Concurrent writes should complete in < 10 seconds")


class TestResourceLimits(unittest.TestCase):
    """Test system behavior under resource constraints"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_memory_efficiency(self):
        """Test memory efficiency with large datasets"""
        print("\n[TEST] Memory efficiency...")
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create large log file
        log_file = os.path.join(self.temp_dir, 'large_log.jsonl')
        with open(log_file, 'w') as f:
            for i in range(5000):
                event = {
                    "timestamp": "2025-01-01T00:00:00+00:00",
                    "source": "memory",
                    "severity": "High",
                    "yara_match": [f"Rule_{i}"],
                    "pid": i
                }
                f.write(json.dumps(event) + '\n')
        
        # Aggregate without loading all into memory
        stats = aggregate_logs(log_file)
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        print(f"  ✓ Initial memory: {initial_memory:.2f} MB")
        print(f"  ✓ Final memory: {final_memory:.2f} MB")
        print(f"  ✓ Memory increase: {memory_increase:.2f} MB")
        print(f"  ✓ Processed {stats['total_detections']} entries")
        
        # Memory increase should be reasonable (< 50MB for 5000 entries)
        self.assertLess(memory_increase, 50.0, "Memory increase should be < 50MB")


if __name__ == "__main__":
    print("=" * 70)
    print("Performance and Stress Tests")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))
    suite.addTests(loader.loadTestsFromTestCase(TestResourceLimits))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    if result.wasSuccessful():
        print("\n" + "=" * 70)
        print("All performance tests passed!")
        print("=" * 70)
        sys.exit(0)
    else:
        print("\n" + "=" * 70)
        print("Some tests failed!")
        print("=" * 70)
        sys.exit(1)

