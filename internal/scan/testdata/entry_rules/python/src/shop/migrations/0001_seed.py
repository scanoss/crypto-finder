import hashlib

from django.db import migrations


def backfill(apps, schema_editor):
    hashlib.sha3_384(b"seed").hexdigest()


class Migration(migrations.Migration):
    operations = [migrations.RunPython(backfill)]
