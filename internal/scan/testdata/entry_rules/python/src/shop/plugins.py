import hashlib

from shop.registry import commands


# A command decorator that neither click nor typer provides: nothing says the
# function is called, so it is not an entry point.
@commands.command("rotate")
def rotate_plugin():
    return hashlib.sha3_512(b"plugin").hexdigest()
