import hashlib

from django.views import View


def receipt(request):
    return hashlib.sha256(b"django").hexdigest()


class RefundView(View):
    def post(self, request):
        return hashlib.blake2s(b"cbv").hexdigest()
