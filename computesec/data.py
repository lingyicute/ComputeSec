# -*- coding: utf-8 -*-
"""
静态知识库：HSI 检测项说明、推荐内核参数、推荐 sysctl、硬件厂商信誉。
"""

APP_ID = "io.github.lingyicute.ComputeSec"
APP_NAME = "计算安全小助手"
VERSION = "1.0.0"
AUTHOR = "lingyicute"
HOMEPAGE = "https://github.com/lingyicute/ComputeSec"
HARDEN_FLATPAK_URL = "https://github.com/lingyicute/harden-flatpak"

# ---------------------------------------------------------------------------
# HSI (Host Security ID) 检测项知识库
# kind: "os" = 操作系统内可修复, "bios" = 固件设置里可修复, "oem" = 需要厂商固件更新/更换硬件
# ---------------------------------------------------------------------------
HSI_RESULT_ENUM = {
    0: "unknown", 1: "enabled", 2: "not-enabled", 3: "valid", 4: "not-valid",
    5: "locked", 6: "not-locked", 7: "encrypted", 8: "not-encrypted",
    9: "tainted", 10: "not-tainted", 11: "found", 12: "not-found",
    13: "supported", 14: "not-supported",
}
HSI_RESULT_ZH = {
    "unknown": "未知", "enabled": "已启用", "not-enabled": "未启用", "valid": "有效",
    "not-valid": "无效", "locked": "已锁定", "not-locked": "未锁定", "encrypted": "已加密",
    "not-encrypted": "未加密", "tainted": "已污染", "not-tainted": "未污染", "found": "存在",
    "not-found": "不存在", "supported": "支持", "not-supported": "不支持",
}
HSI_FLAG_BITS = {
    1 << 0: "success", 1 << 1: "obsoleted", 1 << 2: "missing-data",
    1 << 8: "runtime-updates", 1 << 9: "runtime-attestation", 1 << 10: "runtime-issue",
    1 << 11: "action-contact-oem", 1 << 12: "action-config-fw", 1 << 13: "action-config-os",
}

HSI_ATTRS = {
    "org.fwupd.hsi.Uefi.SecureBoot": dict(
        name="UEFI 安全启动", kind="bios",
        meaning="固件只允许执行由受信任密钥签名的引导加载器、内核与模块，是整个信任链的起点。",
        risk="攻击者可以篡改引导链植入 Bootkit（如 BlackLotus），在操作系统加载之前就获得持久化控制；同时 Linux 内核 Lockdown 也不会自动启用。",
        fix="重启进入固件设置（通常按 F2 / Del / F12），在 Security 或 Boot 菜单中启用 Secure Boot，并确保已恢复出厂密钥（Restore Factory Keys）。Fedora、Ubuntu、openSUSE 等主流发行版均原生支持安全启动。"),
    "org.fwupd.hsi.Uefi.Pk": dict(
        name="UEFI 平台密钥 (PK)", kind="oem",
        meaning="平台密钥不应是固件厂商（如 AMI）遗留的公开测试密钥。",
        risk="若 PK 是已泄露的测试密钥（2024 年曝光的 PKfail 事件），攻击者可签名任意引导程序，安全启动形同虚设。",
        fix="联系 OEM 获取修复固件（通过 fwupdmgr update 或厂商官网）。进阶用户可以使用 sbctl 注册自己的 PK/KEK/db 密钥。"),
    "org.fwupd.hsi.Uefi.Bootservice.Vars": dict(
        name="UEFI 引导服务变量", kind="oem",
        meaning="仅供引导阶段使用的 UEFI 变量不应在运行时暴露给操作系统。",
        risk="运行时可读写这些变量可能泄漏敏感数据或让恶意软件篡改引导配置。",
        fix="需要 OEM 固件更新修复。"),
    "org.fwupd.hsi.Uefi.Db": dict(
        name="UEFI 签名数据库 (db)", kind="os",
        meaning="db 中不应包含已被撤销或已知有漏洞的证书（如 Microsoft UEFI CA 2011）。",
        risk="已知存在漏洞的旧版引导程序仍能被加载，BlackLotus 之类的 Bootkit 可绕过安全启动。",
        fix="运行 `fwupdmgr refresh --force && fwupdmgr update` 应用 dbx 撤销列表更新；新证书（Microsoft UEFI CA 2023）通常由 OEM 固件更新提供。"),
    "org.fwupd.hsi.Uefi.MemoryProtection": dict(
        name="UEFI 内存保护", kind="oem",
        meaning="固件应启用 NX、栈保护等内存防护特性。",
        risk="固件中的内存破坏漏洞更容易被利用来执行任意代码。",
        fix="需要 OEM 固件更新修复。"),
    "org.fwupd.hsi.Tpm.Version20": dict(
        name="TPM 2.0", kind="bios",
        meaning="系统应具备 TPM 2.0 可信平台模块，用于度量启动、密钥密封与远程证明。",
        risk="无法进行可信度量与密钥密封，全盘加密密钥只能依赖口令，也无法检测引导链篡改。",
        fix="在固件设置中启用 TPM（Intel 称 PTT，AMD 称 fTPM），并确保 TPM 处于 2.0 模式。"),
    "org.fwupd.hsi.Tpm.EmptyPcr": dict(
        name="TPM PCR 非空", kind="oem",
        meaning="TPM 平台配置寄存器应当记录了引导阶段的度量值。",
        risk="PCR 为空说明固件没有正确度量引导过程，无法进行远程证明，磁盘密钥可能被错误解封。",
        fix="更新固件；若仍存在问题需联系 OEM。"),
    "org.fwupd.hsi.Tpm.ReconstructionPcr0": dict(
        name="TPM PCR0 可重建", kind="oem",
        meaning="fwupd 应能根据 TPM 事件日志重建 PCR0 的值，从而验证固件度量一致。",
        risk="无法验证固件度量的完整性，可能表明固件被篡改或事件日志损坏。",
        fix="更新固件到最新版本；若仍失败，请联系 OEM。"),
    "org.fwupd.hsi.Spi.Bioswe": dict(
        name="SPI 写使能 (BIOSWE)", kind="oem",
        meaning="SPI 闪存的 BIOS 区域不应允许操作系统直接写入。",
        risk="恶意软件可直接改写固件，植入重装系统也无法清除的持久后门。",
        fix="需要 OEM 固件更新修复。"),
    "org.fwupd.hsi.Spi.Ble": dict(
        name="SPI BIOS 锁定 (BLE)", kind="oem",
        meaning="BIOS Lock Enable 位应被设置，任何写入尝试都会触发 SMI 检查。",
        risk="固件可被任意改写。",
        fix="需要 OEM 固件更新修复。"),
    "org.fwupd.hsi.Spi.SmmBwp": dict(
        name="SPI SMM 写保护", kind="oem",
        meaning="只有在系统管理模式 (SMM) 下才能写 BIOS 区域。",
        risk="非 SMM 代码可绕过保护改写固件。",
        fix="需要 OEM 固件更新修复。"),
    "org.fwupd.hsi.Spi.Descriptor": dict(
        name="SPI 闪存描述符", kind="oem",
        meaning="闪存描述符区域应为只读。",
        risk="攻击者可修改区域访问权限，进而改写 ME/BIOS 区域。",
        fix="需要 OEM 固件更新修复。"),
    "org.fwupd.hsi.Mei.ManufacturingMode": dict(
        name="Intel ME 制造模式", kind="oem",
        meaning="Intel 管理引擎不应仍处于制造模式。",
        risk="制造模式下可任意重写 ME 固件与安全熔丝，完全绕过 Boot Guard。",
        fix="需要 OEM 固件更新（关闭制造模式）。"),
    "org.fwupd.hsi.Mei.OverrideStrap": dict(
        name="Intel ME 描述符覆盖", kind="oem",
        meaning="不应设置闪存描述符覆盖引脚 (HDA_SDO)。",
        risk="允许写入整个 SPI 闪存，包括 ME 区域。",
        fix="需要 OEM 固件更新修复。"),
    "org.fwupd.hsi.Mei.Version": dict(
        name="Intel ME 固件版本", kind="oem",
        meaning="ME 固件不应存在已知严重漏洞（如 CVE-2017-5705 等）。",
        risk="攻击者可利用 ME 漏洞在操作系统之下获得最高权限并长期潜伏。",
        fix="通过 fwupdmgr update 或 OEM 官网更新 ME 固件。"),
    "org.fwupd.hsi.Mei.KeyManifest": dict(
        name="Intel ME 密钥清单", kind="oem",
        meaning="固件签名密钥不应是已泄露的 OEM 密钥（如 2023 年 MSI 泄漏事件涉及的 Boot Guard 密钥）。",
        risk="攻击者可用泄露私钥签署恶意固件，Boot Guard 防护被彻底绕过。",
        fix="联系 OEM。若密钥已泄漏且无法更换，则该硬件不适合高安全计算。"),
    "org.fwupd.hsi.PlatformDebugEnabled": dict(
        name="平台调试接口", kind="bios",
        meaning="Intel DCI / JTAG 等硬件调试接口应被禁用。",
        risk="物理接触者可通过 USB 调试口直接读取内存、控制 CPU，绕过全部软件防护。",
        fix="在固件设置中禁用 Debug Interface / DCI；若无此选项需 OEM 更新固件。"),
    "org.fwupd.hsi.PlatformDebugLocked": dict(
        name="平台调试已锁定", kind="oem",
        meaning="调试接口应通过熔丝被永久锁定。",
        risk="调试接口可被重新开启。",
        fix="需要 OEM 修复。"),
    "org.fwupd.hsi.PlatformFused": dict(
        name="平台熔丝已烧录", kind="oem",
        meaning="生产熔丝应已烧录，表示平台处于正式量产安全状态。",
        risk="未熔丝的平台可能允许加载未签名固件。",
        fix="需要 OEM 修复。"),
    "org.fwupd.hsi.Iommu": dict(
        name="IOMMU", kind="os",
        meaning="IOMMU 限制 PCIe/Thunderbolt 设备只能访问被明确分配的内存区域。",
        risk="任意 DMA 设备（雷电扩展坞、恶意 PCIe 卡、甚至有漏洞的网卡固件）可直接读写全部物理内存、窃取密钥。",
        fix="1) 在固件设置中启用 VT-d (Intel) 或 AMD-Vi/IOMMU (AMD)；2) 添加内核参数：Intel 平台 `intel_iommu=on iommu=force iommu.passthrough=0 iommu.strict=1`，AMD 平台 `amd_iommu=force_isolation iommu=force iommu.passthrough=0 iommu.strict=1`。详见“内核加固”页面。"),
    "org.fwupd.hsi.PrebootDma": dict(
        name="预引导 DMA 防护", kind="bios",
        meaning="固件在引导阶段就应启用 IOMMU，保护操作系统接管前的内存。",
        risk="引导阶段的 DMA 攻击可以篡改内核镜像或读取磁盘加密密钥。",
        fix="在固件设置中启用 Kernel DMA Protection / Thunderbolt Security Level，或更新固件。"),
    "org.fwupd.hsi.IntelBootguard.Enabled": dict(
        name="Intel Boot Guard 已启用", kind="oem",
        meaning="Boot Guard 由 CPU 在执行 BIOS 前验证固件签名。",
        risk="固件被改写后没有任何硬件机制可以发现。",
        fix="Boot Guard 由 OEM 在出厂时通过熔丝配置，用户无法自行开启。"),
    "org.fwupd.hsi.IntelBootguard.Verified": dict(
        name="Intel Boot Guard 验证模式", kind="oem",
        meaning="Boot Guard 应处于验证 (Verified) 模式，而不只是度量模式。",
        risk="被篡改的固件仍会被执行。", fix="需 OEM 出厂配置。"),
    "org.fwupd.hsi.IntelBootguard.Acm": dict(
        name="Intel Boot Guard ACM", kind="oem",
        meaning="认证代码模块应受保护。", risk="Boot Guard 可被绕过。", fix="需 OEM 修复。"),
    "org.fwupd.hsi.IntelBootguard.Policy": dict(
        name="Intel Boot Guard 策略", kind="oem",
        meaning="验证失败时策略应为立即关机，而不是继续启动。",
        risk="即使检测到固件被篡改，系统仍继续启动。", fix="需 OEM 出厂配置。"),
    "org.fwupd.hsi.IntelBootguard.Otp": dict(
        name="Intel Boot Guard OTP 熔丝", kind="oem",
        meaning="Boot Guard 配置应已写入一次性可编程熔丝。",
        risk="配置可被修改。", fix="需 OEM 出厂配置。"),
    "org.fwupd.hsi.IntelCet.Enabled": dict(
        name="控制流强制技术 (CET) 支持", kind="oem",
        meaning="CPU 应支持 CET（影子栈与间接分支跟踪），抵御 ROP/JOP 攻击。",
        risk="内存破坏漏洞更容易被利用为任意代码执行。",
        fix="属于 CPU 特性（Intel 11 代 / AMD Zen 3 及以后）。无法通过软件修复。"),
    "org.fwupd.hsi.IntelCet.Active": dict(
        name="CET 已激活", kind="os",
        meaning="内核与用户态应实际启用了 CET 防护。",
        risk="硬件具备但未启用，仍无法抵御 ROP 攻击。",
        fix="使用较新的内核（≥ 6.2 支持内核 IBT，≥ 6.6 支持用户态影子栈）且不要添加 `ibt=off`；确保 glibc 与发行版已启用 CET 编译选项。"),
    "org.fwupd.hsi.IntelSmap": dict(
        name="SMAP", kind="oem",
        meaning="管理模式访问保护阻止内核意外访问用户空间内存。",
        risk="内核漏洞更容易被利用。", fix="属于 CPU 特性，无法软件修复。"),
    "org.fwupd.hsi.EncryptedRam": dict(
        name="内存加密", kind="bios",
        meaning="系统内存应被透明加密（AMD TSME / Intel TME）。",
        risk="冷启动攻击或物理探针可直接读取内存中的密钥与明文数据。",
        fix="在固件设置中启用 TSME（AMD）或 Total Memory Encryption（Intel）。AMD 平台还需内核参数 `mem_encrypt=on`。"),
    "org.fwupd.hsi.SuspendToIdle": dict(
        name="挂起到空闲 (s2idle)", kind="bios",
        meaning="系统应使用 s2idle 而非传统 S3 挂起。",
        risk="S3 挂起时内存保持供电且通常未加密，攻击者可通过冷启动攻击读取密钥。",
        fix="在固件设置中把睡眠模式改为 Windows/Linux (Modern Standby)；并可添加内核参数 `mem_sleep_default=s2idle`。"),
    "org.fwupd.hsi.SuspendToRam": dict(
        name="挂起到内存 (S3) 已禁用", kind="bios",
        meaning="系统不应支持 S3 挂起。",
        risk="同上，S3 使冷启动攻击成为可能。",
        fix="在固件设置中禁用 S3 / 选择 Modern Standby。"),
    "org.fwupd.hsi.Amd.RollbackProtection": dict(
        name="AMD 固件回滚保护", kind="bios",
        meaning="应禁止把固件降级到存在已知漏洞的旧版本。",
        risk="攻击者可刷回有漏洞的旧固件后加以利用。",
        fix="在固件设置中启用 Rollback Protection / Anti-Rollback；或联系 OEM。"),
    "org.fwupd.hsi.Amd.SpiWriteProtection": dict(
        name="AMD SPI 写保护", kind="oem",
        meaning="SPI 闪存应受 PSP 写保护。", risk="固件可被任意改写。", fix="需 OEM 固件更新。"),
    "org.fwupd.hsi.Amd.SpiReplayProtection": dict(
        name="AMD SPI 重放保护", kind="oem",
        meaning="应启用 SPI 重放保护。", risk="旧固件镜像可被回写。", fix="需 OEM 固件更新。"),
    "org.fwupd.hsi.Amd.SmmLocked": dict(
        name="AMD SMM 已锁定", kind="oem",
        meaning="系统管理模式应被锁定。", risk="SMM 可被恶意代码利用。", fix="需 OEM 固件更新。"),
    "org.fwupd.hsi.SupportedCpu": dict(
        name="CPU 仍受支持", kind="oem",
        meaning="CPU 应仍在厂商的支持周期内，可获得微码更新。",
        risk="新发现的侧信道漏洞（Spectre 家族等）将不再获得微码修补。",
        fix="无法软件修复，考虑更换较新的硬件。"),
    "org.fwupd.hsi.BiosCapsuleUpdates": dict(
        name="固件胶囊更新", kind="bios",
        meaning="固件应支持 UEFI Capsule 更新，这样才能通过 fwupd/LVFS 及时修补。",
        risk="固件漏洞难以被及时修复。",
        fix="在固件设置中启用 UEFI Capsule Update / Windows UEFI Firmware Update；或联系 OEM。"),
    "org.fwupd.hsi.BiosRollbackProtection": dict(
        name="固件回滚保护", kind="bios",
        meaning="应禁止把固件降级到旧版本。", risk="攻击者可刷回有漏洞的旧固件。",
        fix="在固件设置中启用 Anti-Rollback。"),
    "org.fwupd.hsi.Kernel.Tainted": dict(
        name="内核未被污染", kind="os",
        meaning="内核不应加载了非树内、未签名或专有模块。",
        risk="专有/未审计模块运行在最高权限，可能包含漏洞或后门，且使整个内核不可信。",
        fix="运行 `cat /proc/sys/kernel/tainted` 查看原因；卸载 NVIDIA 私有驱动、VirtualBox、未签名的 DKMS 模块等，或改用已签名的替代方案。"),
    "org.fwupd.hsi.Kernel.Lockdown": dict(
        name="内核 Lockdown", kind="os",
        meaning="Lockdown 阻止 root 修改运行中的内核（禁止 /dev/mem、未签名模块、kexec 等）。",
        risk="获得 root 的攻击者可以直接修改内核代码，绕过安全启动建立的信任链。",
        fix="启用 UEFI 安全启动后多数发行版会自动进入 integrity 模式；要达到最高级别请添加内核参数 `lockdown=confidentiality`。详见“内核加固”页面。"),
    "org.fwupd.hsi.Kernel.Swap": dict(
        name="交换分区已加密", kind="os",
        meaning="交换空间（swap）必须加密或使用 zram。",
        risk="内存中的密钥、密码、明文文档会被换出到磁盘并长期保留。",
        fix="推荐使用 zram（Fedora 默认，`sudo dnf install zram-generator-defaults`）；或在 LUKS 卷内建立 swap，或 `swapoff -a` 后删除未加密的交换分区。"),
    "org.fwupd.hsi.Fwupd.Plugins": dict(
        name="fwupd 插件", kind="os",
        meaning="fwupd 的安全相关插件应全部正常加载。",
        risk="部分检测无法执行，结果不完整。",
        fix="确保安装了发行版官方的完整 fwupd 包并重启 fwupd 服务：`sudo systemctl restart fwupd`。"),
    "org.fwupd.hsi.Fwupd.Updates": dict(
        name="固件为最新", kind="os",
        meaning="所有可通过 LVFS 更新的固件应为最新版本。",
        risk="已知固件漏洞未被修补。",
        fix="运行 `fwupdmgr refresh --force && fwupdmgr update`，或在 GNOME 软件 / KDE Discover 中安装固件更新。"),
    "org.fwupd.hsi.Fwupd.Attestation": dict(
        name="固件可证明", kind="os",
        meaning="应能借助 TPM 事件日志对固件进行远程证明。",
        risk="无法验证固件是否被篡改。",
        fix="确保 TPM 已启用并且 `/sys/kernel/security/tpm0/binary_bios_measurements` 可读；更新固件。"),
    "org.fwupd.hsi.HostEmulation": dict(
        name="非仿真主机", kind="os",
        meaning="fwupd 不应处于主机仿真模式。", risk="检测结果不真实。", fix="不要使用 fwupd 的仿真数据。"),
}
# 别名（较新 fwupd 版本重命名的条目）
HSI_ALIASES = {
    "org.fwupd.hsi.Cet.Enabled": "org.fwupd.hsi.IntelCet.Enabled",
    "org.fwupd.hsi.Cet.Active": "org.fwupd.hsi.IntelCet.Active",
    "org.fwupd.hsi.Smap": "org.fwupd.hsi.IntelSmap",
    "org.fwupd.hsi.Bios.RollbackProtection": "org.fwupd.hsi.BiosRollbackProtection",
}
HSI_KIND_ZH = {"os": "在操作系统中修复", "bios": "在固件设置 (BIOS/UEFI) 中修复", "oem": "需要厂商 (OEM) 固件更新"}

# ---------------------------------------------------------------------------
# 推荐内核参数
# arch: 适用架构集合； cpu: None / "intel" / "amd" 仅在对应 CPU 上评估
# 注意：root=、rootflags=、rw、rhgb、quiet、vconsole.keymap 等属于机器专属参数，已从推荐列表中排除。
# ---------------------------------------------------------------------------
X = ("x86_64",)
A = ("aarch64",)
XA = ("x86_64", "aarch64")

KERNEL_PARAMS = [
    dict(key="hash_pointers", value="always", arch=XA, desc="始终对 printk 输出的指针进行哈希，防止内核地址泄漏（内核 ≥ 6.17）。"),
    dict(key="init_on_alloc", value="1", arch=XA, desc="分配内存时清零，防止未初始化内存导致的信息泄漏。"),
    dict(key="init_on_free", value="1", arch=XA, desc="释放内存时清零，减少 use-after-free 与数据残留。", note="有少量性能开销。"),
    dict(key="intel_iommu", value="on", arch=X, cpu="intel", desc="启用 Intel VT-d IOMMU，抵御 DMA 攻击。"),
    dict(key="amd_iommu", value="force_isolation", arch=X, cpu="amd", desc="启用 AMD IOMMU 并强制为所有设备做隔离。"),
    dict(key="iommu.passthrough", value="0", arch=XA, desc="禁止 DMA 直通，所有设备都必须经过 IOMMU 地址转换。"),
    dict(key="iommu.strict", value="1", arch=XA, desc="严格模式：解除映射时立即失效 IOTLB，杜绝短暂的时间窗口。", note="I/O 性能略有下降。"),
    dict(key="iommu", value="force", arch=X, desc="即使内存较小也强制启用 IOMMU。"),
    dict(key="kvm_amd.sev", value="1", arch=X, cpu="amd", desc="允许 KVM 使用 AMD SEV 加密虚拟机内存。"),
    dict(key="kvm_amd.sev_es", value="1", arch=X, cpu="amd", desc="启用 SEV-ES（加密寄存器状态）。"),
    dict(key="kvm_amd.sev_snp", value="1", arch=X, cpu="amd", desc="启用 SEV-SNP（内存完整性保护）。"),
    dict(key="kvm-intel.vmentry_l1d_flush", value="always", arch=X, cpu="intel", desc="每次进入虚拟机都刷新 L1D 缓存，缓解 L1TF。"),
    dict(key="kvm.mitigate_smt_rsb", value="1", arch=X, desc="缓解跨 SMT 线程的 RSB 侧信道攻击。"),
    dict(key="l1d_flush", value="on", arch=X, cpu="intel", desc="允许进程通过 prctl 请求上下文切换时刷新 L1D。"),
    dict(key="l1tf", value="full,force", arch=X, cpu="intel", desc="L1 终端故障完整缓解并禁用 SMT。", note="会关闭超线程。"),
    dict(key="lockdown", value="confidentiality", arch=XA, desc="最高级别内核锁定：禁止 root 读取内核内存、加载未签名模块、kexec 等。", note="可能影响休眠、DKMS 模块、部分调试工具。"),
    dict(key="loglevel", value="0", arch=XA, desc="控制台不输出内核日志，减少信息泄漏。"),
    dict(key="mitigations", value={"x86_64": "auto,nosmt", "aarch64": "auto"}, arch=XA, desc="启用全部 CPU 漏洞缓解措施；x86 上同时关闭 SMT。", note="x86 上关闭超线程会降低多线程性能。"),
    dict(key="module.sig_enforce", value="1", arch=XA, desc="只允许加载签名的内核模块。", note="NVIDIA 私有驱动、VirtualBox 等未签名模块将无法加载。"),
    dict(key="page_alloc.shuffle", value="1", arch=XA, desc="随机化页分配器空闲列表，增加堆布局不可预测性。"),
    dict(key="proc_mem.force_override", value="ptrace", arch=XA, desc="仅允许通过 ptrace 写 /proc/PID/mem，禁止 FOLL_FORCE 写入。"),
    dict(key="pti", value="on", arch=X, desc="强制页表隔离，缓解 Meltdown。"),
    dict(key="kpti", value="on", arch=A, desc="ARM64 内核页表隔离，缓解 Meltdown 类攻击。"),
    dict(key="random.trust_bootloader", value="off", arch=XA, desc="不信任引导程序提供的随机种子。"),
    dict(key="random.trust_cpu", value="off", arch=XA, desc="不信任 CPU 硬件 RNG（RDRAND）作为唯一熵源。"),
    dict(key="randomize_kstack_offset", value="on", arch=XA, desc="每次系统调用随机化内核栈偏移。"),
    dict(key="rd.emergency", value="halt", arch=XA, desc="initramfs 出错时直接关机而不进入紧急 shell。"),
    dict(key="rd.shell", value="0", arch=XA, desc="禁止 initramfs 提供 root shell（防物理攻击者绕过认证）。"),
    dict(key="slab_debug", value="FZ", arch=XA, desc="启用 slab 完整性检查与红区，检测堆溢出。", note="有性能开销。"),
    dict(key="slab_nomerge", value=None, arch=XA, desc="禁止合并 slab 缓存，增加堆利用难度。"),
    dict(key="spec_store_bypass_disable", value="on", arch=XA, desc="无条件启用 Spectre v4 (SSB) 缓解。"),
    dict(key="spectre_v2", value="on", arch=XA, desc="无条件启用 Spectre v2 缓解。"),
    dict(key="ssbd", value="force-on", arch=XA, desc="强制开启推测存储绕过禁用。"),
    dict(key="systemd.ssh_auto", value="no", arch=XA, desc="禁止 systemd 自动生成 SSH 监听（AF_VSOCK/本地套接字）。"),
    dict(key="vdso32", value="0", arch=XA, desc="禁用 32 位 vDSO。"),
    dict(key="vsyscall", value="none", arch=X, desc="彻底禁用固定地址的 vsyscall 页，消除 ROP 跳板。", note="极老的 glibc（< 2.14）程序无法运行。"),
    dict(key="ia32_emulation", value="0", arch=X, desc="禁用 32 位系统调用兼容层，减少攻击面。", note="Steam、Wine 等 32 位程序将无法运行。"),
    dict(key="bdev_allow_write_mounted", value="0", arch=XA, desc="禁止对已挂载的块设备直接写入。", note="部分磁盘工具可能受影响。"),
    dict(key="debugfs", value="off", arch=XA, desc="关闭 debugfs，减少内核信息暴露。", note="部分性能/调试工具将不可用。"),
    dict(key="efi", value="disable_early_pci_dma", arch=XA, desc="EFI 启动早期禁用 PCI 总线主控，阻止早期 DMA 攻击。"),
    dict(key="gather_data_sampling", value="force", arch=X, cpu="intel", desc="强制缓解 Downfall (GDS)，即使没有微码也禁用 AVX。", note="可能影响 AVX 性能。"),
    dict(key="mem_encrypt", value="on", arch=X, cpu="amd", desc="启用 AMD 透明内存加密 (SME)。"),
    dict(key="oops", value="panic", arch=XA, desc="内核 oops 时直接 panic，防止在损坏状态下继续被利用。"),
    dict(key="irqchip.gicv3_pseudo_nmi", value="1", arch=A, desc="启用 GICv3 伪 NMI，改善 ARM64 上的 hardlockup 检测。"),
    dict(key="rodata", value="full", arch=A, desc="ARM64 上完整的只读数据保护（含 linear map）。"),
]
KERNEL_MACHINE_SPECIFIC_NOTE = ("以下参数属于机器专属配置，不在推荐列表中评估：root=、rootflags=、rw、rhgb、quiet、vconsole.keymap 等。"
                                "请不要照搬他人的 root=UUID=...。")

# ---------------------------------------------------------------------------
# 推荐 sysctl
# cmp: "eq" 精确匹配（默认）； "ge" 实际值 >= 期望值即可
# ---------------------------------------------------------------------------
SYSCTL_GROUPS = [
    ("网络安全加固", [
        dict(key="net.ipv4.tcp_syncookies", value="1", desc="抵御 SYN Flood。"),
        dict(key="net.ipv4.tcp_rfc1337", value="1", desc="防御 TIME-WAIT 暗杀攻击。"),
        dict(key="net.ipv4.icmp_echo_ignore_broadcasts", value="1", desc="忽略广播 ping，防 Smurf 放大攻击。"),
        dict(key="net.ipv4.icmp_ignore_bogus_error_responses", value="1", desc="忽略伪造的 ICMP 错误。"),
        dict(key="net.ipv4.icmp_echo_ignore_all", value="1", desc="不回应任何 ping，降低被扫描发现的概率。", note="本机将无法被 ping 到。"),
        dict(key="net.ipv6.icmp.echo_ignore_all", value="1", desc="IPv6 同上。"),
        dict(key="net.ipv4.tcp_timestamps", value="0", desc="关闭 TCP 时间戳，防止运行时间指纹泄漏。"),
        dict(key="net.ipv4.conf.all.rp_filter", value="1", desc="反向路径过滤，防 IP 欺骗。"),
        dict(key="net.ipv4.conf.default.rp_filter", value="1", desc="新接口默认反向路径过滤。"),
        dict(key="net.ipv4.conf.*.send_redirects", value="0", desc="不发送 ICMP 重定向（本机不是路由器）。"),
        dict(key="net.ipv4.conf.*.accept_redirects", value="0", desc="不接受 ICMP 重定向，防中间人劫持路由。"),
        dict(key="net.ipv6.conf.*.accept_redirects", value="0", desc="IPv6 同上。"),
        dict(key="net.ipv4.conf.*.shared_media", value="0", desc="不假定接口共享介质。"),
        dict(key="net.ipv4.conf.*.arp_filter", value="1", desc="ARP 只在正确的接口上应答。"),
        dict(key="net.ipv4.conf.*.arp_ignore", value="2", desc="仅回应目标 IP 与来源同网段的 ARP 请求。"),
        dict(key="net.ipv4.conf.all.drop_gratuitous_arp", value="1", desc="丢弃免费 ARP，防 ARP 欺骗。"),
        dict(key="net.ipv4.conf.*.accept_source_route", value="0", desc="拒绝源路由报文。"),
        dict(key="net.ipv6.conf.*.accept_source_route", value="0", desc="IPv6 同上。"),
        dict(key="net.ipv6.conf.all.use_tempaddr", value="2", desc="优先使用 IPv6 临时隐私地址。"),
        dict(key="net.ipv6.conf.default.use_tempaddr", value="2", desc="新接口默认使用临时隐私地址。"),
        dict(key="net.ipv4.conf.all.log_martians", value="1", desc="记录来源可疑的数据包。"),
        dict(key="net.ipv4.conf.default.log_martians", value="1", desc="新接口同上。"),
    ]),
    ("eBPF 与内核漏洞缓解", [
        dict(key="net.core.bpf_jit_harden", value="2", desc="对所有用户的 BPF JIT 进行加固（常量致盲）。"),
        dict(key="kernel.yama.ptrace_scope", value="1", cmp="ge", desc="限制 ptrace 只能附加到子进程，防止凭据窃取。"),
        dict(key="kernel.unprivileged_bpf_disabled", value="1", desc="禁止非特权 eBPF（eBPF 是内核漏洞利用的高发区）。"),
        dict(key="kernel.sysrq", value="0", desc="禁用 SysRq 魔术键。"),
        dict(key="kernel.perf_event_paranoid", value="3", cmp="ge", desc="禁止非特权用户使用 perf（侧信道与信息泄漏）。"),
        dict(key="kernel.kptr_restrict", value="2", desc="对所有用户隐藏内核指针。"),
        dict(key="kernel.dmesg_restrict", value="1", desc="只允许 root 读取内核日志。"),
        dict(key="kernel.oops_limit", value="100", desc="oops 超过 100 次即 panic，阻止靠反复 oops 进行的利用（内核 ≥ 6.2）。"),
        dict(key="kernel.warn_limit", value="100", desc="WARN 超过 100 次即 panic（内核 ≥ 6.2）。"),
        dict(key="kernel.panic", value="-1", desc="panic 后立即重启。"),
        dict(key="kernel.printk", value="3 3 3 3", desc="限制控制台日志级别，减少信息泄漏。"),
        dict(key="kernel.kexec_load_disabled", value="1", desc="禁止 kexec 加载新内核（一旦设为 1 不可撤销）。"),
        dict(key="kernel.core_pattern", value="|/bin/false", desc="不生成核心转储，避免内存中的机密写入磁盘。"),
        dict(key="kernel.io_uring_disabled", value="2", desc="彻底禁用 io_uring（近年大量提权漏洞的来源，内核 ≥ 6.6）。", note="少数高性能应用依赖 io_uring。"),
    ]),
    ("文件系统安全", [
        dict(key="fs.binfmt_misc.status", value="0", desc="禁用 binfmt_misc，防止注册恶意解释器。"),
        dict(key="fs.suid_dumpable", value="0", desc="SUID 程序不生成核心转储。"),
        dict(key="fs.protected_regular", value="2", desc="限制在全局可写目录中打开他人创建的普通文件。"),
        dict(key="fs.protected_fifos", value="2", desc="限制在全局可写目录中打开他人创建的 FIFO。"),
        dict(key="fs.protected_hardlinks", value="1", desc="限制硬链接创建，防 TOCTOU 攻击。"),
        dict(key="fs.protected_symlinks", value="1", desc="限制符号链接跟随。"),
        dict(key="dev.tty.ldisc_autoload", value="0", desc="禁止非特权自动加载 TTY 行规程模块。"),
        dict(key="vm.unprivileged_userfaultfd", value="0", desc="禁止非特权 userfaultfd（常用于延长内核竞争窗口）。"),
    ]),
    ("内存 ASLR", [
        dict(key="kernel.randomize_va_space", value="2", desc="完整 ASLR（含 brk）。"),
        dict(key="vm.mmap_min_addr", value="65536", cmp="ge", desc="禁止映射低地址，防 NULL 指针解引用利用。"),
        dict(key="vm.max_map_count", value="1048576", cmp="ge", desc="提高映射数上限，配合更高的 ASLR 熵。"),
        dict(key="vm.mmap_rnd_bits", value="32", cmp="ge", desc="64 位程序 mmap 随机化位数（越大越好，上限取决于内核）。"),
        dict(key="vm.mmap_rnd_compat_bits", value="16", cmp="ge", desc="32 位兼容程序 mmap 随机化位数。"),
    ]),
]
SYSCTL_AARCH64_NOTE = ("您使用的是 aarch64 系统：vm.mmap_rnd_bits 与 vm.mmap_rnd_compat_bits 的最大值取决于内核编译时的页大小与虚拟地址位数。"
                       "建议在终端中手动尝试逐步增大，探索所用内核支持的最大值，例如：\n"
                       "  sudo sysctl vm.mmap_rnd_bits=33\n  sudo sysctl vm.mmap_rnd_bits=34\n"
                       "直到提示 Invalid argument 为止，然后把最大可用值写入 /etc/sysctl.d/。在 Fedora aarch64 中，vm.mmap_rnd_bits 最大值通常为 33。")

# ---------------------------------------------------------------------------
# 硬件厂商信誉
# rating: good / neutral / caution / bad
# ---------------------------------------------------------------------------
VENDORS = [
    dict(match=["lenovo", "thinkpad", "ideapad", "legion", "thinkcentre", "thinkbook"], name="联想 Lenovo", rating="bad",
         incidents=[
             ("2015 · Superfish", "在消费级笔记本预装 Superfish 广告软件，植入自签名根证书对 HTTPS 流量进行中间人拦截；其私钥可被轻易提取，导致全体用户暴露于 MITM 攻击。"),
             ("2015 · Lenovo Service Engine (LSE)", "利用 Windows Platform Binary Table 在 BIOS 中内置代码，即便用户全新安装 Windows 也会被自动下载并执行联想程序（rootkit 式持久化），且该组件存在缓冲区溢出漏洞。"),
             ("2017 · FTC 和解", "美国联邦贸易委员会就 Superfish 事件与联想达成和解，要求其在 20 年内接受第三方安全审计。"),
             ("2018 · Fingerprint Manager Pro", "指纹管理软件使用硬编码口令并以弱加密方式存储 Windows 登录凭据。"),
             ("2022 · UEFI 固件漏洞", "ESET 披露 100 余款联想笔记本存在可绕过安全启动的 UEFI 漏洞 (CVE-2022-3430/3431/3432)。"),
         ],
         advice="联想的固件层曾出现过厂商主动植入的持久化组件。不建议将此硬件用于高安全性计算。若必须使用，请刷入 coreboot（部分老款 ThinkPad 支持）或至少启用安全启动并保持固件更新，完全重装系统并拒绝所有厂商预装服务。"),
    dict(match=["asus", "asustek"], name="华硕 ASUS", rating="bad",
         incidents=[
             ("2019 · ShadowHammer", "华硕 Live Update 更新服务器被攻陷，攻击者用华硕合法证书签名的后门程序被推送给约 100 万台电脑，属于典型的供应链攻击。"),
             ("2022 · Cyclops Blink", "国家级 APT 组织利用华硕路由器固件构建僵尸网络。"),
             ("2025 · DriverHub RCE", "预装的 DriverHub 存在一键式远程代码执行漏洞 (CVE-2025-3462/3463)，任意网站可诱导安装驱动。"),
             ("2025 · Armoury Crate LPE", "Armoury Crate 驱动存在本地提权漏洞 (CVE-2025-3464)。"),
         ],
         advice="华硕的官方更新渠道曾被用于分发签名后门，意味着“来自厂商的更新”本身不可信。不建议用于高安全性计算；若使用，请禁用/卸载所有 ASUS 预装工具与 Armoury Crate，只使用发行版及 LVFS 提供的更新。"),
    dict(match=["msi", "micro-star"], name="微星 MSI", rating="bad",
         incidents=[
             ("2023 · Boot Guard 私钥泄漏", "MSI 遭 Money Message 勒索组织入侵，泄漏了 Intel Boot Guard 的 OEM 私钥和固件签名密钥，涉及数十款 MSI 主板/笔记本；攻击者可用泄漏密钥签署恶意固件，硬件信任根被永久破坏。"),
             ("2024 · MSI Center 提权", "MSI Center 存在本地提权漏洞 (CVE-2024-22076)。"),
         ],
         advice="受影响型号的 Boot Guard 密钥已经泄漏且无法在硬件层面撤销。强烈不建议将 MSI 设备用于高安全性计算。"),
    dict(match=["gigabyte", "aorus"], name="技嘉 Gigabyte", rating="bad",
         incidents=[
             ("2023 · UEFI 后门式更新器", "Eclypsium 发现 271 款技嘉主板的 UEFI 固件会在每次启动时向 Windows 注入并执行更新程序，通过不安全的 HTTP 下载代码，行为与固件后门无异。"),
             ("2021 · RansomEXX 入侵", "内部 112 GB 数据被窃，包括 Intel/AMD 的 NDA 技术文档。"),
             ("2025 · UEFI SMM 漏洞", "多款技嘉主板 UEFI 固件存在可绕过安全启动的 SMM 漏洞，部分老型号不再修复。"),
         ],
         advice="技嘉固件曾内置可被劫持的自动下载执行机制，强烈不建议用于高安全性计算；若使用，请在固件中关闭 APP Center Download & Install，并更新到最新 BIOS。"),
    dict(match=["dell", "alienware"], name="戴尔 Dell", rating="caution",
         incidents=[
             ("2015 · eDellRoot", "预装了自签名根证书且私钥随机附带，允许对全体用户进行 HTTPS 中间人攻击。"),
             ("2019 · SupportAssist RCE", "预装的 SupportAssist 允许远程网站以 SYSTEM 权限执行代码 (CVE-2019-3719)。"),
             ("2021 · dbutil_2_3.sys", "预装驱动存在 12 年之久的提权漏洞 (CVE-2021-21551)，影响数亿台设备。"),
             ("2021 · BIOSConnect", "固件级远程更新功能存在证书校验缺陷 (CVE-2021-21571)，可被中间人劫持 BIOS 更新。"),
         ],
         advice="戴尔的问题多集中在预装软件与更新机制，且修复响应较快。可谨慎用于中等安全需求。请禁用 BIOSConnect，不要安装 SupportAssist，并保持 LVFS 固件更新。"),
    dict(match=["hp", "hewlett", "hewlett-packard", "omen", "elitebook", "probook"], name="惠普 HP", rating="caution",
         incidents=[
             ("2017 · Conexant 音频驱动键盘记录器", "预装音频驱动的 MicTray64.exe 将所有按键记录到本地文件。"),
             ("2017 · Touchpoint Analytics", "通过 Windows 更新静默安装遥测软件。"),
             ("2022 · UEFI 固件漏洞", "Binarly 报告多个 HP UEFI SMM 漏洞，部分型号修复滞后数月。"),
         ],
         advice="HP 有预装软件层面的隐私事故。可谨慎使用；请勿安装厂商附加软件，并保持固件更新。"),
    dict(match=["acer", "predator"], name="宏碁 Acer", rating="caution",
         incidents=[
             ("2016 · 电商数据泄漏", "在线商店客户支付卡信息泄漏。"),
             ("2021 · REvil 勒索攻击", "遭勒索软件入侵，被索要 5000 万美元赎金；同年印度与台湾办公室再次被入侵。"),
             ("2022 · UEFI 安全启动绕过", "多款 Acer 笔记本固件存在可禁用安全启动的漏洞 (CVE-2022-4020)。"),
         ],
         advice="宏碁的事故主要涉及企业自身安全治理与固件质量。可谨慎使用，请保持固件更新。"),
    dict(match=["samsung"], name="三星 Samsung", rating="caution",
         incidents=[
             ("2015 · SW Update", "预装的 SW Update 会主动关闭 Windows Update。"),
             ("2023 · 内部数据经 ChatGPT 泄漏", "员工将芯片源码上传至外部 AI 服务。"),
         ],
         advice="三星 PC 曾有干扰系统更新的行为。可谨慎使用，避免安装厂商附加软件。"),
    dict(match=["supermicro", "super micro"], name="Supermicro", rating="caution",
         incidents=[
             ("2018 · “The Big Hack” 报道", "彭博社称其主板被植入间谍芯片，虽被多方否认且未被独立证实，但引发广泛担忧。"),
             ("2019 · USBAnywhere", "BMC 虚拟介质服务允许未认证的远程 USB 设备接入。"),
             ("2024 · BMC 固件漏洞", "多个 IPMI/BMC 高危漏洞 (CVE-2024-36435 等)。"),
         ],
         advice="服务器 BMC 是常见攻击面。若用于高安全性计算，请将 BMC 置于独立管理网段或物理断开。"),
    dict(match=["huawei", "honor", "matebook"], name="华为 / 荣耀", rating="caution",
         incidents=[
             ("2019 · PCManager 驱动", "微软发现 MateBook 预装驱动的行为与 NSA DoublePulsar 后门类似，存在提权漏洞 (CVE-2019-5241)。"),
             ("2019 起 · 多国政府限制", "多国以国家安全为由限制其设备用于敏感领域。"),
         ],
         advice="出于供应链透明度和政府干预可能性的考虑，强烈不建议用于高安全性计算。"),
    dict(match=["xiaomi", "redmi", "timi"], name="小米 Xiaomi", rating="caution",
         incidents=[
             ("2016 · AnalyticsCore", "预装组件可静默下载安装任意 APK。"),
             ("2020 · 浏览器数据收集", "研究者发现小米浏览器即使在隐身模式下也将浏览记录上传至远程服务器。"),
         ],
         advice="小米在隐私方面有争议记录，不建议用于高安全性计算。如需使用，切勿安装任何厂商软件。"),
    dict(match=["apple", "macbook", "mac mini", "imac"], name="Apple", rating="good",
         incidents=[("说明", "Apple 硬件具备 Secure Enclave、安全启动与内存加密等强硬件安全特性，公开重大硬件后门事件较少；但固件完全闭源，Linux 支持依赖 Asahi 社区。")],
         advice="硬件安全设计优秀，但不可审计。高安全场景请权衡闭源固件风险。"),
    dict(match=["framework"], name="Framework", rating="good",
         incidents=[("说明", "模块化、可维修设计，公开 EC 固件源码，部分型号支持 coreboot 社区移植，安全透明度较高。")],
         advice="很好的选择，请继续保持固件更新。"),
    dict(match=["system76"], name="System76", rating="good",
         incidents=[("说明", "使用开源 coreboot 固件与开源嵌入式控制器固件，透明度极高。")],
         advice="很好的选择，请继续保持固件更新。"),
    dict(match=["purism", "librem"], name="Purism", rating="good",
         incidents=[("说明", "coreboot + PureBoot 可验证启动，硬件断路开关，禁用 Intel ME。")],
         advice="很好的选择，请继续保持固件更新。"),
    dict(match=["tuxedo"], name="TUXEDO Computers", rating="good",
         incidents=[("说明", "专注 Linux 的厂商，部分型号提供 coreboot 固件。")],
         advice="很好的选择，请继续保持固件更新。"),
    dict(match=["star labs", "starlabs"], name="Star Labs", rating="good",
         incidents=[("说明", "提供 coreboot 开源固件，可通过 LVFS 更新。")],
         advice="很好的选择，请继续保持固件更新。"),
    dict(match=["novacustom", "nova custom"], name="NovaCustom", rating="good",
         incidents=[("说明", "采用 Dasharo (coreboot) 开源固件，注重隐私与可审计性。")],
         advice="很好的选择，请继续保持固件更新。"),
    dict(match=["google", "chromebook", "pixelbook"], name="Google (Chromebook)", rating="good",
         incidents=[("说明", "coreboot + 验证启动 + Titan 安全芯片，硬件安全架构成熟。")],
         advice="不错的选择，请继续保持固件更新。"),
    dict(match=["microsoft", "surface"], name="Microsoft Surface", rating="neutral",
         incidents=[("说明", "固件闭源但安全设计规范（Project Mu），无重大公开硬件后门事件。")],
         advice="可以使用，请通过 LVFS 继续保持固件更新。"),
    dict(match=["raspberry pi"], name="Raspberry Pi", rating="neutral",
         incidents=[("说明", "VideoCore GPU 的启动固件闭源，且缺少安全启动/TPM 等硬件安全特性（Pi 4/5 可选安全启动）。")],
         advice="适合学习与低敏感场景；不建议用于高安全性计算。"),
    dict(match=["qemu", "kvm", "vmware", "virtualbox", "innotek", "hyper-v", "virtual machine", "parallels", "bochs", "xen"], name="虚拟机", rating="neutral",
         incidents=[("说明", "您正在虚拟机中运行。虚拟机的安全性完全取决于宿主机与虚拟化平台。")],
         advice="请在宿主机上运行本工具，对真实硬件进行安全评估。"),
    dict(match=["intel"], name="Intel (NUC / 参考设计)", rating="neutral",
         incidents=[("说明", "Intel 平台存在 ME 等闭源子系统，历史上多次曝出 ME 漏洞 (CVE-2017-5689 等)，但更新较为及时。")],
         advice="可以使用，请继续保持固件更新。"),
]
DEFAULT_VENDOR = dict(name="未收录厂商", rating="neutral",
                      incidents=[("说明", "本工具的知识库中没有该厂商的重大安全/隐私事故记录。这绝不代表安全，仅表示梨没有对该品牌进行研究。")],
                      advice="请自行检索该厂商的固件更新政策与安全公告，并保持固件更新。")

RATING_ZH = {"good": "信誉良好", "neutral": "无重大记录", "caution": "需谨慎", "bad": "不建议用于高安全计算"}
RATING_SCORE = {"good": 100, "neutral": 75, "caution": 40, "bad": 10}

# 桌面环境自带 / 运行时相关的 Flatpak 前缀（不计入用户主动安装数）
FLATPAK_EXCLUDE_PREFIXES = ("org.gnome.", "org.kde.", "org.fedoraproject.", "org.freedesktop.", "io.elementary.", APP_ID)

# 已知 2.4G 无线接收器（厂商 ID 或 产品字符串关键词）
USB_24G_VENDORS = {
    "046d": "Logitech", "25a7": "Areson/Compx (通用 2.4G)", "3938": "MOSART Semi (通用 2.4G)", "062a": "MosArt (通用 2.4G)",
    "1d57": "Xenta / Compx (通用 2.4G)", "248a": "Maxxter / Telink (通用 2.4G)", "1a2c": "China Resource Semico", "0c45": "Microdia / Sonix",
    "04d9": "Holtek", "1ea7": "SHARKOON / 通用 2.4G", "2ea8": "Primax", "3151": "Yichip", "1bcf": "Sunplus", "3554": "Compx",
}
USB_24G_KEYWORDS = ["2.4g", "2.4 g", "wireless receiver", "receiver", "dongle", "unifying", "lightspeed", "nano", "usb receiver", "wireless mouse", "wireless keyboard"]
LOGITECH_UNIFYING_PIDS = {"c52b", "c532", "c534", "c52f", "c531", "c537", "c539", "c53a", "c53f", "c541", "c545"}
LOGITECH_BOLT_PIDS = {"c548"}
