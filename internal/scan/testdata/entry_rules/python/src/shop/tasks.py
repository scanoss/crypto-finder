import hashlib

from celery import shared_task


@shared_task
def reconcile():
    return hashlib.sha384(b"celery").hexdigest()


def orphan():
    # Nothing calls it and no rule makes it an entry point.
    return hashlib.sha3_256(b"orphan").hexdigest()
