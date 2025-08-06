import unittest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from task_lab_63 import TaskImplementation, quick_process

class TestTaskImplementation(unittest.TestCase):
    """Test cases for TaskImplementation."""

    def setUp(self):
        """Set up test fixtures."""
        self.implementation = TaskImplementation()

    def test_initialization(self):
        """Test proper initialization."""
        self.assertEqual(self.implementation.task_id, "LAB-63")
        self.assertEqual(self.implementation.description, "We need to implement a user profile management system that allows users to view and update their personal information.

h2. Requirements:

* Users should be able to view their current profile information
* Users should be able to update their name, email, and bio
* Profile updates should be validated before saving
* The system should show success/error messages appropriately

h2. Technical Details:

* Create a new API endpoint for profile management
* Add proper input validation
* Include error handling for database operations
* Follow existing code patterns in the project

h2. Acceptance Criteria:

* [ ] GET /api/profile endpoint returns current user profile
* [ ] PUT /api/profile endpoint allows profile updates
* [ ] Input validation prevents invalid data
* [ ] Appropriate HTTP status codes are returned
* [ ] Error messages are user-friendly
* [ ] Unit tests cover the new functionality")
        self.assertEqual(self.implementation.status, "initialized")

    def test_process_data_string(self):
        """Test processing string data."""
        result = self.implementation.process_data("hello")

        self.assertIsInstance(result, dict)
        self.assertEqual(result['task_id'], "LAB-63")
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
        self.assertEqual(stats['task_id'], "LAB-63")

    def test_quick_process(self):
        """Test quick process function."""
        result = quick_process("test")

        self.assertIsInstance(result, dict)
        self.assertEqual(result['status'], 'completed')
        self.assertIn('output', result)

if __name__ == '__main__':
    unittest.main(verbosity=2)
