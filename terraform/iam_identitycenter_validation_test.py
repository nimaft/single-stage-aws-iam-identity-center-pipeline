import unittest
from validation.iam_identitycenter_validation import (
    validate_unique_permission_set_name,
)


class TestValidateUniquePermissionSetName(unittest.TestCase):

    def test_unique_permission_set_names(
        self,
    ):
        permission_set_templates = {
            "template1": {"Name": "PermissionSet1"},
            "template2": {"Name": "PermissionSet2"},
            "template3": {"Name": "PermissionSet3"},
        }
        result = validate_unique_permission_set_name(permission_set_templates)
        self.assertEqual(result, [])

    def test_duplicate_permission_set_names(
        self,
    ):
        permission_set_templates = {
            "template1": {"Name": "PermissionSet1"},
            "template2": {"Name": "PermissionSet2"},
            "template3": {"Name": "PermissionSet1"},
        }
        result = validate_unique_permission_set_name(permission_set_templates)
        self.assertEqual(len(result), 1)
        self.assertIn("Duplicate Permission Set Names", result[0])
        self.assertIn("PermissionSet1", result[0])

    def test_missing_name_key_raises(
        self,
    ):
        """
        A permission set file with no Name key cannot be checked for uniqueness, so
        this validator raises rather than returning an error string.
        """
        permission_set_templates = {"template1": {"Description": "No name here"}}
        with self.assertRaises(Exception) as context:
            validate_unique_permission_set_name(permission_set_templates)
        self.assertIn("template1", str(context.exception))


if __name__ == "__main__":
    unittest.main()
