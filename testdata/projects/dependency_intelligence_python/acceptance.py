# Copyright (C) 2026 SCANOSS.COM
# SPDX-License-Identifier: GPL-2.0-only
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

from Cryptodome.Cipher import AES


class BaseRunner:
    def run(self, data: bytes, key: bytes, runtime_provider: str) -> bytes:
        raise NotImplementedError


def leaf(data: bytes, key: bytes, size: int) -> bytes:
    return data


def helper(data: bytes, key: bytes, size: int) -> bytes:
    return leaf(data, key, size)


def provider_probe(provider: str) -> None:
    pass


class Runner(BaseRunner):
    def run(self, data: bytes, key: bytes, runtime_provider: str) -> bytes:
        provider_probe("pycryptodomex")
        provider_probe(runtime_provider)
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.encrypt(data)
        helper(data, key, 16)
        return data
