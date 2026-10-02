import hashlib

from django.db import migrations


def backfill(apps, schema_editor):
    hashlib.sha3_224(b"nested").hexdigest()


class Migration(migrations.Migration):
    operations = [migrations.RunPython(backfill)]
