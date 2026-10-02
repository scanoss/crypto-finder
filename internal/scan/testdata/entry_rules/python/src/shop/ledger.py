import hashlib

from django.db import migrations


def reindex(apps, schema_editor):
    hashlib.pbkdf2_hmac("sha256", b"p", b"s", 10)


class Migration(migrations.Migration):
    operations = [migrations.RunPython(reindex)]
