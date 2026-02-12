import unittest
    import subprocess  # Mock this in real tests!
    from your_module import execute_command, CommandExecutionError  # Replace your_module

    class TestExecuteCommand(unittest.TestCase):

        def test_allowed_command(self):
            return_code, stdout, stderr = execute_command('ls', ['.'])
            self.assertEqual(return_code, 0)  # Assuming 'ls .' succeeds

        def test_disallowed_command(self):
            with self.assertRaises(CommandExecutionError):
                execute_command('rm', ['-rf', '/'])

        def test_argument_sanitization(self):
            # This is a simplified example.  In a real test, you'd need to
            # mock subprocess and assert that the command is called with
            # the expected sanitized arguments.
            return_code, stdout, stderr = execute_command('ls', ["file with spaces", "; rm -rf /"])
            self.assertEqual(return_code, 0) # Assuming 'ls' with these args runs

        def test_command_not_found(self):
            with self.assertRaises(CommandExecutionError):
                execute_command('nonexistent_command')

        def test_command_failure(self):
            # Test a command that is allowed but fails (e.g., 'cat a_file_that_does_not_exist')
            with self.assertRaises(CommandExecutionError):
                execute_command('cat', ['a_file_that_does_not_exist'])

    if __name__ == '__main__':
        unittest.main()

