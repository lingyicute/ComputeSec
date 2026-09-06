<div align="center">

# 计算安全小助手 · ComputeSec

<p align="center">
  <img src="data/icons/hicolor/scalable/apps/uk._92li.lingyicute.ComputeSec.svg" width="128" alt="ComputeSec 图标">
</p>

**一个基于 **GTK4 / libadwaita / Python** 的 Linux 桌面安全评估工具。它会读取你的系统状态，与安全基线对比，用通俗的语言解释每一项检查的意义与缺失的危害，并给出可以直接复制粘贴的修复方法。做得好的地方会用绿色告诉你：继续保持！🤗**

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](./LICENSE)

<p align="center">
  [🇨🇳 中文] • <a href="README.en.md">🇺🇸 English</a> •
  <a href="https://s.92li.uk/">🌐 官方网站</a> •
  <a href="https://github.com/lingyicute/ComputeSec/releases">📦 获取</a> •
  <a href="https://github.com/lingyicute/ComputeSec/issues">🐛 报告问题</a>
</p>

![Screenshot](./screenshot/screenshot.png)

</div>

---

## 功能页面

### 1. 仪表盘
* **核心内容**：综合评分、四大板块卡片、待办摘要。

### 2. HSI 固件安全
* **状态获取**：通过 fwupd D-Bus（或 `fwupdmgr security`）获取 Host Security ID (HSI) 检测结果。
* **风险解读**：逐项解释各项检测的含义以及未开启/缺失时的安全危害。
* **修复指引（“您可以修复”栏目）**：
  * 按 **“操作系统内”** 与 **“固件设置中”** 分组提供具体操作步骤。
  * 涵盖要点：IOMMU、Kernel Lockdown、加密 swap、Secure Boot、TPM、s2idle 等。

### 3. 内核加固
* **状态读取与对比**：
  * 读取 `/proc/cmdline` 与 `/proc/sys`（等价于 `sysctl -a`）。
  * 程序会根据您的当前架构，分别与内置 amd64 / aarch64 推荐 kargs 列表及 sysctl 加固列表进行对比。
* **快速修复与指引**：
  * 支持一键复制缺失参数。
  * 提供 `grubby` / GRUB / systemd-boot / rpm-ostree 的配置方法。
  * 提供 `/etc/sysctl.d` 配置文件生成与设置指引。
* **特殊架构提示**：在 aarch64 平台上，提示手动探索 `vm.mmap_rnd_bits` 的最大值。

### 4. 硬件品牌
* **厂商识别**：读取 DMI / 设备树识别硬件厂商。
* **信誉库对照**：对比内置的厂商安全信誉库（详细记载了联想 Superfish/LSE、华硕 ShadowHammer、MSI Boot Guard 私钥泄漏、技嘉 UEFI 后门式更新器、戴尔 eDellRoot 等历史事件）。
* **安全建议**：对存在安全污点的品牌，提示建议不要用于高安全性计算环境。

### 5. 使用习惯
* **Flatpak 生态评估**：
  * 统计应用数量（自动排除运行时与桌面环境自带包）。
  * 数量不足 5 个时建议多使用 Flatpak。
  * 推荐使用梨的 [harden-flatpak](https://github.com/lingyicute/harden-flatpak) 项目，默认拒绝所有 Flatpak 权限，并辅以 Flatseal 进行权限加固。
* **运行时间提醒**：检测到系统 `uptime` 超过一天时，提醒进行更新和重启。
* **外设安全检测**：检测是否存在 2.4G 无线接收器，提示潜在的按键嗅探风险。
* **环境隔离检测**：检测是否存在 NTFS 分区或 Windows 系统安装（提示不可审计、可能污染 Linux 环境）。

## 方式一：克隆直接运行

依赖：Python ≥ 3.9、PyGObject、GTK 4、libadwaita ≥ 1.4（Fedora 39+ / Ubuntu 24.04+ / Debian 13+ / Arch），以及 `fwupd`（用于 HSI）。

```bash
# Fedora
sudo dnf install python3-gobject gtk4 libadwaita fwupd
# Debian / Ubuntu
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 fwupd
# Arch
sudo pacman -S python-gobject gtk4 libadwaita fwupd
```

```bash
git clone https://github.com/lingyicute/ComputeSec.git
cd ComputeSec
python3 run.py
```

想让它出现在应用菜单里、并让任务栏/Dock 正确显示图标（Wayland 下需要 `.desktop` 文件与 App ID 匹配）：

```bash
python3 run.py --install     # 安装 .desktop 与 SVG 图标到 ~/.local/share
python3 run.py --uninstall   # 移除
```

## 方式二：Flatpak

### 从 Release 安装

在 [Releases](https://github.com/lingyicute/ComputeSec/releases) 下载对应架构的 `.flatpak`：

```bash
flatpak install --user ./ComputeSec-x86_64.flatpak
flatpak run uk._92li.lingyicute.ComputeSec
```

### 本地构建

```bash
flatpak install flathub org.gnome.Platform//50 org.gnome.Sdk//50
flatpak-builder --user --install --force-clean build-dir uk._92li.lingyicute.ComputeSec.json
flatpak run uk._92li.lingyicute.ComputeSec
```

### Flatpak 权限说明

本工具需要读取宿主机信息，因此请求了以下权限（可用 Flatseal 随时收回，对应功能会显示“无法获取”）：

| 权限 | 用途 |
| --- | --- |
| `--system-talk-name=org.freedesktop.fwupd` | 通过 D-Bus 读取 HSI 结果 |
| `--talk-name=org.freedesktop.Flatpak` | 在 `fwupdmgr`、`lsblk`、`flatpak list` 需要时通过 `flatpak-spawn --host` 执行（仅只读命令） |
| `--filesystem=/var/lib/flatpak:ro`、`~/.local/share/flatpak:ro` | 统计已安装的 Flatpak 应用 |
| `--filesystem=/run/udev:ro`、`/boot/efi:ro`、`/efi:ro` | 检测 NTFS 分区与 Windows 引导器 |

`/proc/cmdline`、`/proc/sys`、`/sys/class/dmi`、`/sys/bus/usb` 在沙箱内默认可读，无需额外权限。

## 项目结构

```
run.py                  启动器（克隆运行 / Flatpak 内为 /app/bin/computesec）
computesec/
  ├── main.py           应用与窗口、导航、后台检测线程
  ├── ui.py             五个页面的构建
  ├── checks.py         数据采集与比对（fwupd、cmdline、sysctl、DMI、Flatpak、uptime、USB、NTFS）
  └── data.py           知识库：HSI 说明、内核参数、sysctl、厂商信誉
data/
  └── 图标和构建信息
uk._92li.lingyicute.ComputeSec.json      Flatpak 清单
.github/workflows/build.yml               Build Workflow
```

## 注意事项

- 内核参数列表中的 `root=`、`rootflags=`、`rw`、`rhgb`、`quiet`、`vconsole.keymap` 等机器专属启动配置项不会被评估，请勿照搬他人的 `root=UUID=...`。
- 部分加固参数有微小副作用（例如 `module.sig_enforce=1` 会阻止 NVIDIA 私有驱动加载，`ia32_emulation=0` 会让 Steam/Wine 无法运行，`mitigations=auto,nosmt` 会关闭超线程），页面中已逐项标注 ⚠。建议先在 GRUB 菜单按 `e` 临时添加试运行一次。

> [!IMPORTANT]
> 出于安全性上的考虑，梨不建议您使用 NVIDIA 闭源驱动和闭源内核模块，也不建议您使用 Wine 运行来源未知的 Windows 程序。

- 厂商信誉信息来自公开报道与 CVE 记录，仅供参考。

## 🗂️ License

This program is released under the GNU General Public License v3.0 (GPLv3).

Copyright © 2025-2026 lingyicute.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses.
