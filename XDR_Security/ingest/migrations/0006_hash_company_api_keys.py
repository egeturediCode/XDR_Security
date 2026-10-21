import hashlib

from django.db import migrations
from django.db import models

import ingest.models


HASH_PREFIX = "sha256$"


def hash_existing_api_keys(apps, schema_editor):
    Company = apps.get_model("ingest", "Company")
    database = schema_editor.connection.alias

    for company in Company.objects.using(database).all().iterator():
        if company.api_key and not company.api_key.startswith(HASH_PREFIX):
            digest = hashlib.sha256(company.api_key.encode("utf-8")).hexdigest()
            company.api_key = f"{HASH_PREFIX}{digest}"
            company.save(update_fields=["api_key"])


class Migration(migrations.Migration):

    dependencies = [
        ("ingest", "0005_assets_asset_type_assets_criticality_and_more"),
    ]

    operations = [
        migrations.RunPython(hash_existing_api_keys),
        migrations.AlterField(
            model_name="company",
            name="api_key",
            field=models.CharField(
                db_index=True,
                default=ingest.models.generate_api_key,
                help_text="Dış sistemlerin gönderdiği anahtarın SHA-256 özeti.",
                max_length=255,
                unique=True,
            ),
        ),
    ]
