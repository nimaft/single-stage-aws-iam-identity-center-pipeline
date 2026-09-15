import unittest
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
from validation.iam_identitycenter_validation import (
    build_customer_policy_arn,
    validate_managed_policies_arn,
    validate_unique_permission_set_name,
)


def client_error(code: str) -> ClientError:
    """Builds a ClientError with the given error code, as boto3 would raise it."""
    return ClientError({"Error": {"Code": code, "Message": code}}, "GetPolicy")


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


class TestBuildCustomerPolicyArn(unittest.TestCase):
    """
    An IAM policy ARN has exactly one slash between "policy" and the path. The old
    code concatenated a hard-coded slash with the Path from the template, so a
    correct Path of "/pbounds/" produced "policy//pbounds/" and only an incorrect
    Path with no leading slash produced a valid ARN.
    """

    def test_path_with_leading_and_trailing_slash(self):
        self.assertEqual(
            build_customer_policy_arn("123456789012", "/pbounds/", "MyPolicy"),
            "arn:aws:iam::123456789012:policy/pbounds/MyPolicy",
        )

    def test_path_without_slashes(self):
        self.assertEqual(
            build_customer_policy_arn("123456789012", "pbounds", "MyPolicy"),
            "arn:aws:iam::123456789012:policy/pbounds/MyPolicy",
        )

    def test_nested_path(self):
        self.assertEqual(
            build_customer_policy_arn("123456789012", "/sso/global/", "MyPolicy"),
            "arn:aws:iam::123456789012:policy/sso/global/MyPolicy",
        )

    def test_root_path(self):
        for path in ["/", "", None]:
            self.assertEqual(
                build_customer_policy_arn("123456789012", path, "MyPolicy"),
                "arn:aws:iam::123456789012:policy/MyPolicy",
                f"path {path!r}",
            )


class TestValidateManagedPoliciesArn(unittest.TestCase):

    @patch("boto3.client")
    def test_no_managed_policies_key(self, mock_boto3_client):
        """
        ManagedPolicies is optional: a permission set may use only CustomPolicy or
        only CustomerManagedPolicies. Reading the key directly raised a KeyError that
        the except ClientError block could not catch, so validation crashed.
        """
        mock_boto3_client.return_value = MagicMock()
        permission_set = {
            "Name": "InlineOnly",
            "CustomPolicy": {"Version": "2012-10-17", "Statement": []},
        }

        result = validate_managed_policies_arn(permission_set, "123456789012")

        self.assertEqual(result, [])

    @patch("boto3.client")
    def test_reports_every_missing_policy(self, mock_boto3_client):
        """
        The loop was inside the try block, so the first missing policy stopped the
        remaining policies from being checked.
        """
        mock_iam = MagicMock()
        mock_iam.get_policy.side_effect = [
            client_error("NoSuchEntity"),
            {"Policy": {}},
            client_error("NoSuchEntity"),
        ]
        mock_boto3_client.return_value = mock_iam
        permission_set = {
            "Name": "ThreePolicies",
            "ManagedPolicies": ["arn:one", "arn:two", "arn:three"],
        }

        result = validate_managed_policies_arn(permission_set, "123456789012")

        self.assertEqual(len(result), 2)
        self.assertIn("arn:one", result[0])
        self.assertIn("arn:three", result[1])

    @patch("boto3.client")
    def test_reraises_access_denied(self, mock_boto3_client):
        """
        A reported finding must mean "the template is wrong". If the validator cannot
        read IAM, it must fail loudly rather than report a missing policy.
        """
        mock_iam = MagicMock()
        mock_iam.get_policy.side_effect = client_error("AccessDenied")
        mock_boto3_client.return_value = mock_iam
        permission_set = {"Name": "Denied", "ManagedPolicies": ["arn:one"]}

        with self.assertRaises(ClientError):
            validate_managed_policies_arn(permission_set, "123456789012")

    @patch("boto3.client")
    def test_permission_boundary_without_a_path(self, mock_boto3_client):
        """
        Path is optional, and the resolver defaults a missing Path to "/". Reading the
        key directly raised a KeyError, so validation rejected input that the resolver
        accepts.
        """
        mock_iam = MagicMock()
        mock_iam.get_policy.return_value = {"Policy": {}}
        mock_boto3_client.return_value = mock_iam
        permission_set = {
            "Name": "BoundaryNoPath",
            "CustomerPermissionBoundary": {"Name": "MyBoundary"},
        }

        result = validate_managed_policies_arn(permission_set, "123456789012")

        self.assertEqual(result, [])
        mock_iam.get_policy.assert_called_once_with(
            PolicyArn="arn:aws:iam::123456789012:policy/MyBoundary"
        )

    @patch("boto3.client")
    def test_permission_boundary_arn_has_a_single_slash(self, mock_boto3_client):
        mock_iam = MagicMock()
        mock_iam.get_policy.return_value = {"Policy": {}}
        mock_boto3_client.return_value = mock_iam
        permission_set = {
            "Name": "BoundaryWithPath",
            "CustomerPermissionBoundary": {"Path": "/pbounds/", "Name": "MyBoundary"},
        }

        result = validate_managed_policies_arn(permission_set, "123456789012")

        self.assertEqual(result, [])
        mock_iam.get_policy.assert_called_once_with(
            PolicyArn="arn:aws:iam::123456789012:policy/pbounds/MyBoundary"
        )

    @patch("boto3.client")
    def test_permission_boundary_arn_instead_of_name(self, mock_boto3_client):
        mock_boto3_client.return_value = MagicMock()
        permission_set = {
            "Name": "BoundaryArn",
            "CustomerPermissionBoundary": {
                "Name": "arn:aws:iam::123456789012:policy/MyBoundary"
            },
        }

        result = validate_managed_policies_arn(permission_set, "123456789012")

        self.assertEqual(len(result), 1)
        self.assertIn("instead of name", result[0])


if __name__ == "__main__":
    unittest.main()
