import unittest
from unittest.mock import patch
import templates_metadata


class TemplateReleaseTests(unittest.TestCase):
    def resolve(self, reference, tag=False):
        responses = [{'tag_name':'v10.5.0','draft':False,'prerelease':False}, {'object':reference}]
        if tag:
            responses.append({'object':{'type':'commit','sha':'b'*40}})
        with patch('templates_metadata.github', side_effect=responses):
            return templates_metadata.resolve()

    def test_lightweight_release_resolves_to_immutable_commit(self):
        result = self.resolve({'type':'commit','sha':'a'*40})
        self.assertEqual(result, {'templates_version':'v10.5.0','templates_revision':'a'*40})

    def test_annotated_tag_is_peeled(self):
        self.assertEqual(self.resolve({'type':'tag','sha':'a'*40}, tag=True)['templates_revision'],'b'*40)

    def test_non_commit_or_invalid_sha_fails(self):
        for reference in [{'type':'tree','sha':'a'*40},{'type':'commit','sha':'main'}]:
            with self.assertRaises(AssertionError):
                self.resolve(reference)

    def test_prerelease_does_not_enter_images(self):
        with patch('templates_metadata.github', return_value={'tag_name':'v1.0.0-rc.1','draft':False,'prerelease':True}):
            with self.assertRaises(AssertionError):
                templates_metadata.resolve()
