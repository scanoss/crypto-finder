import hashlib

import click


@click.command()
def export():
    return hashlib.blake2b(b"click").hexdigest()
