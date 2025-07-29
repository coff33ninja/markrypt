#!/usr/bin/env python3
"""
Comprehensive test runner for Markrypt
"""

import os
import sys
import unittest
import time
import json
from pathlib import Path
from datetime import datetime

# Add the parent package to the path so we can import markrypt modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from test_core import TestMarkryptCore
from test_high_level import TestHighLevelAPI
from test_cli import TestMarkryptCLI


class MarkryptTestRunner:
    """Comprehensive test runner with different test levels"""
    
    def __init__(self, output_dir=None):
        self.output_dir = Path(output_dir) if output_dir else Path(__file__).parent / "output"
        self.output_dir.mkdir(exist_ok=True)
        self.results = {}
        self.start_time = None
        self.end_time = None
    
    def run_quick_tests(self):
        """Run quick smoke tests"""
        print("🚀 Running Quick Tests (Smoke Tests)")
        print("=" * 50)
        
        suite = unittest.TestSuite()
        
        # Add essential tests
        suite.addTest(TestMarkryptCore('test_small_text_with_noise'))
        suite.addTest(TestMarkryptCore('test_small_text_without_noise'))
        suite.addTest(TestHighLevelAPI('test_encrypt_decrypt_text'))
        
        return self._run_suite(suite, "quick")
    
    def run_standard_tests(self):
        """Run standard test suite"""
        print("🧪 Running Standard Tests")
        print("=" * 50)
        
        suite = unittest.TestSuite()
        
        # Core tests
        core_tests = [
            'test_small_text_with_noise',
            'test_small_text_without_noise',
            'test_large_text_auto_disable_noise',
            'test_unicode_text',
            'test_different_keys',
            'test_integrity_check',
            'test_noise_styles'
        ]
        
        for test in core_tests:
            suite.addTest(TestMarkryptCore(test))
        
        # High-level API tests
        api_tests = [
            'test_encrypt_decrypt_text',
            'test_large_text_handling',
            'test_unicode_text_handling',
            'test_batch_operations',
            'test_safe_decrypt'
        ]
        
        for test in api_tests:
            suite.addTest(TestHighLevelAPI(test))
        
        return self._run_suite(suite, "standard")
    
    def run_comprehensive_tests(self):
        """Run comprehensive test suite"""
        print("🔬 Running Comprehensive Tests")
        print("=" * 50)
        
        # Load all test classes
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        
        # Add all tests
        suite.addTests(loader.loadTestsFromTestCase(TestMarkryptCore))
        suite.addTests(loader.loadTestsFromTestCase(TestHighLevelAPI))
        suite.addTests(loader.loadTestsFromTestCase(TestMarkryptCLI))
        
        return self._run_suite(suite, "comprehensive")
    
    def run_performance_tests(self):
        """Run performance tests with different text sizes"""
        print("⚡ Running Performance Tests")
        print("=" * 50)
        
        import markrypt
        from markrypt.encrypt import MarkryptEncryptor
        
        fixtures_dir = Path(__file__).parent / "fixtures"
        
        # Test different text sizes
        test_cases = [
            ("Single char", (fixtures_dir / "single_char.txt").read_text(encoding='utf-8')),
            ("Small text", (fixtures_dir / "small_text.txt").read_text(encoding='utf-8')),
            ("Large text", (fixtures_dir / "large_text.txt").read_text(encoding='utf-8')),
            ("Unicode text", (fixtures_dir / "unicode_text.txt").read_text(encoding='utf-8'))
        ]
        
        results = []
        
        for name, text in test_cases:
            print(f"\nTesting {name} ({len(text)} chars)...")
            
            # Core API performance
            start_time = time.time()
            mk = markrypt.Markrypt(noise=True)
            encrypted = mk.encrypt(text, mapping_key='perf123')
            decrypted = mk.decrypt(encrypted, mapping_key='perf123')
            core_time = time.time() - start_time
            
            # High-level API performance
            start_time = time.time()
            encryptor = MarkryptEncryptor()
            encrypted_hl = encryptor.encrypt_text(text, key='perf123')
            decryptor = markrypt.decrypt.MarkryptDecryptor()
            decrypted_hl = decryptor.decrypt_text(encrypted_hl, key='perf123')
            hl_time = time.time() - start_time
            
            # Verify correctness
            core_correct = text == decrypted
            hl_correct = text == decrypted_hl
            
            result = {
                'name': name,
                'text_length': len(text),
                'core_time': core_time,
                'hl_time': hl_time,
                'core_correct': core_correct,
                'hl_correct': hl_correct,
                'encrypted_length': len(encrypted),
                'compression_ratio': len(encrypted) / len(text) if text else 0
            }
            
            results.append(result)
            
            print(f"  Core API: {core_time:.4f}s ({'✅' if core_correct else '❌'})")
            print(f"  High-level API: {hl_time:.4f}s ({'✅' if hl_correct else '❌'})")
            print(f"  Compression ratio: {result['compression_ratio']:.2f}x")
        
        # Save performance results
        perf_file = self.output_dir / f"performance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(perf_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n📊 Performance results saved to: {perf_file}")
        return results
    
    def _run_suite(self, suite, test_type):
        """Run a test suite and collect results"""
        self.start_time = time.time()
        
        # Create a custom test result to capture details
        stream = open(os.devnull, 'w')  # Suppress unittest output
        runner = unittest.TextTestRunner(stream=stream, verbosity=0)
        result = runner.run(suite)
        stream.close()
        
        self.end_time = time.time()
        
        # Process results
        total_tests = result.testsRun
        failures = len(result.failures)
        errors = len(result.errors)
        passed = total_tests - failures - errors
        
        # Print summary
        print(f"\n📊 {test_type.title()} Test Results:")
        print(f"  Total tests: {total_tests}")
        print(f"  Passed: {passed} ✅")
        print(f"  Failed: {failures} ❌")
        print(f"  Errors: {errors} 💥")
        print(f"  Duration: {self.end_time - self.start_time:.2f}s")
        
        # Print failures and errors
        if result.failures:
            print(f"\n❌ Failures:")
            for test, traceback in result.failures:
                print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
        
        if result.errors:
            print(f"\n💥 Errors:")
            for test, traceback in result.errors:
                print(f"  - {test}: {traceback.split('Exception:')[-1].strip()}")
        
        # Save detailed results
        test_result = {
            'test_type': test_type,
            'timestamp': datetime.now().isoformat(),
            'duration': self.end_time - self.start_time,
            'total_tests': total_tests,
            'passed': passed,
            'failed': failures,
            'errors': errors,
            'success_rate': passed / total_tests if total_tests > 0 else 0,
            'failures': [{'test': str(test), 'error': tb} for test, tb in result.failures],
            'errors': [{'test': str(test), 'error': tb} for test, tb in result.errors]
        }
        
        # Save to file
        result_file = self.output_dir / f"{test_type}_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(result_file, 'w') as f:
            json.dump(test_result, f, indent=2)
        
        print(f"📄 Detailed results saved to: {result_file}")
        
        self.results[test_type] = test_result
        return test_result


def main():
    """Main test runner function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Markrypt Test Runner')
    parser.add_argument('--level', choices=['quick', 'standard', 'comprehensive', 'performance'], 
                       default='standard', help='Test level to run')
    parser.add_argument('--output-dir', help='Output directory for test results')
    
    args = parser.parse_args()
    
    # Create test runner
    runner = MarkryptTestRunner(args.output_dir)
    
    print(f"🧪 Markrypt Test Suite")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📁 Output directory: {runner.output_dir}")
    print()
    
    # Run tests based on level
    if args.level == 'quick':
        result = runner.run_quick_tests()
    elif args.level == 'standard':
        result = runner.run_standard_tests()
    elif args.level == 'comprehensive':
        result = runner.run_comprehensive_tests()
    elif args.level == 'performance':
        result = runner.run_performance_tests()
        return
    
    # Overall summary
    success_rate = result['success_rate']
    if success_rate == 1.0:
        print(f"\n🎉 All tests passed! ({result['passed']}/{result['total_tests']})")
    elif success_rate >= 0.8:
        print(f"\n✅ Most tests passed ({result['passed']}/{result['total_tests']}) - {success_rate:.1%}")
    else:
        print(f"\n⚠️  Some tests failed ({result['passed']}/{result['total_tests']}) - {success_rate:.1%}")
    
    return result['passed'] == result['total_tests']


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)