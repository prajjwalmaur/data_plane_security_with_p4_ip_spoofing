#!/usr/bin/env python3
"""
P4 IP Spoofing Defense - Complete Test Runner

This script runs all tests for the P4 IP Spoofing Defense project.

Tests included:
1. P4 Behavioral Model Test (simulates BMv2)
2. Security Logic Simulation
3. Mininet Integration (requires root)

Usage:
    python3 run_all_tests.py              # Run behavioral model tests
    sudo python3 run_all_tests.py         # Run all tests including Mininet

Author: Based on "Data-Plane Security Applications in Adversarial Settings"
"""

import sys
import os
import subprocess

def print_header(title: str):
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)

def run_test(name: str, command: list) -> bool:
    """Run a test and return success status"""
    print_header(name)
    try:
        result = subprocess.run(command, capture_output=False)
        return result.returncode == 0
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("=" * 80)
    print("  P4 IP SPOOFING DEFENSE - COMPLETE TEST SUITE")
    print("  Based on: 'Data-Plane Security Applications in Adversarial Settings'")
    print("=" * 80)

    results = {}

    # Test 1: P4 Behavioral Model
    results['P4 Behavioral Model'] = run_test(
        "TEST 1: P4 Behavioral Model (BMv2 Simulation)",
        [sys.executable, "p4_behavioral_model.py"]
    )

    # Test 2: Security Logic Simulation
    results['Security Simulation'] = run_test(
        "TEST 2: Security Logic Simulation",
        [sys.executable, "test_simulation.py"]
    )

    # Test 3: Mininet (if root)
    if os.geteuid() == 0:
        print_header("TEST 3: Mininet Integration")
        print("Running Mininet test...")
        try:
            # Run with timeout
            result = subprocess.run(
                [sys.executable, "mininet_p4_test.py"],
                timeout=60,
                input=b'n\n'  # Don't enter CLI
            )
            results['Mininet Integration'] = result.returncode == 0
        except subprocess.TimeoutExpired:
            print("Mininet test timed out")
            results['Mininet Integration'] = False
        except Exception as e:
            print(f"Mininet test error: {e}")
            results['Mininet Integration'] = False
    else:
        print_header("TEST 3: Mininet Integration (SKIPPED)")
        print("Run with sudo to enable Mininet tests")
        results['Mininet Integration'] = None

    # Summary
    print_header("TEST SUMMARY")

    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)

    for name, result in results.items():
        if result is True:
            status = "[PASS]"
        elif result is False:
            status = "[FAIL]"
        else:
            status = "[SKIP]"
        print(f"  {status} {name}")

    print("-" * 40)
    print(f"  Passed:  {passed}")
    print(f"  Failed:  {failed}")
    print(f"  Skipped: {skipped}")
    print("=" * 80)

    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
