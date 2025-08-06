import unittest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from task_lab_100 import TaskImplementation, quick_process

class TestTaskImplementation(unittest.TestCase):
    """Test cases for TaskImplementation."""

    def setUp(self):
        """Set up test fixtures."""
        self.implementation = TaskImplementation()

    def test_initialization(self):
        """Test proper initialization."""
        self.assertEqual(self.implementation.task_id, "LAB-100")
        self.assertEqual(self.implementation.description, "BMI - FastAPI")
        self.assertEqual(self.implementation.status, "initialized")

    def test_process_data_string(self):
        """Test processing string data."""
        result = self.implementation.process_data("hello")

        self.assertIsInstance(result, dict)
        self.assertEqual(result['task_id'], "LAB-100")
        self.assertEqual(result['status'], 'completed')
        self.assertIn('output', result)

    def test_process_data_number(self):
        """Test processing numerical data."""
        result = self.implementation.process_data(42)

        self.assertIsInstance(result, dict)
        self.assertEqual(result['status'], 'completed')
        self.assertIn('output', result)

    def test_statistics(self):
        """Test statistics generation."""
        self.implementation.process_data("test1")
        self.implementation.process_data("test2")

        stats = self.implementation.get_statistics()

        self.assertIsInstance(stats, dict)
        self.assertEqual(stats['total_processed'], 2)
        self.assertEqual(stats['successful'], 2)
        self.assertEqual(stats['task_id'], "LAB-100")

    def test_quick_process(self):
        """Test quick process function."""
        result = quick_process("test")

        self.assertIsInstance(result, dict)
        self.assertEqual(result['status'], 'completed')
        self.assertIn('output', result)

if __name__ == '__main__':
    unittest.main(verbosity=2)
