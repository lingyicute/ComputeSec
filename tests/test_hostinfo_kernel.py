# -*- coding: utf-8 -*-
import platform

from computesec import hostinfo


def test_host_identity_kernel_strips_whitespace_before_fallback():
    assert hostinfo.HostIdentity(kernel_release="   \t ").kernel == platform.release()
    assert hostinfo.HostIdentity(kernel_release=" 6.18.1-200 ").kernel == "6.18.1-200"
