from django.test import TestCase

from .models import Company, hash_api_key


class CompanyApiKeyTests(TestCase):
    def test_api_key_is_hashed_before_saving(self):
        company = Company.objects.create(name="Test company")

        self.assertNotEqual(company.api_key, company.raw_api_key)
        self.assertEqual(company.api_key, hash_api_key(company.raw_api_key))

    def test_api_key_hash_is_stable(self):
        api_key = "test-api-key"

        self.assertEqual(hash_api_key(api_key), hash_api_key(api_key))
