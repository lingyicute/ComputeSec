# 计算安全小助手 · ComputeSec

<p align="center">
  <img src="data/icons/hicolor/scalable/apps/io.github.lingyicute.ComputeSec.svg" width="128" alt="ComputeSec 图标">
</p>

一个基于 **GTK4 / libadwaita / Python** 的 Linux 桌面安全评估工具。它会读取你的系统状态，与安全基线对比，用通俗的语言解释每一项检查的意义与缺失的危害，并给出可以直接复制粘贴的修复方法。做得好的地方会用绿色告诉你：继续保持！🤗

## 功能页面

| 页面 | 内容 |
| --- | --- |
| **仪表盘** | 综合评分、四大板块卡片、待办摘要 |
| **HSI 固件安全** | 通过 fwupd D-Bus（或 `fwupdmgr security`）获取 Host Security ID 结果；逐项解释含义与缺失危害；**“您可以修复”** 栏目按“操作系统内 / 固件设置中”分组给出操作步骤（IOMMU、Kernel Lockdown、加密 swap、Secure Boot、TPM、s2idle……） |
| **内核加固** | 读取 `/proc/cmdline` 与 `/proc/sys`（等价于 `sysctl -a`），分别与 amd64 / aarch64 推荐参数列表及 sysctl 加固列表对比；一键复制缺失参数、`grubby` / GRUB / systemd-boot / rpm-ostree 设置方法、`/etc/sysctl.d` 配置文件；aarch64 上提示手动探索 `vm.mmap_rnd_bits` 最大值 |
| **硬件品牌** | 读取 DMI / 设备树识别厂商，对照内置信誉库（联想 Superfish/LSE、华硕 ShadowHammer、MSI Boot Guard 私钥泄漏、技嘉 UEFI 后门式更新器、戴尔 eDellRoot……），对有污点的品牌建议不要用于高安全性计算 |
| **使用习惯** | ① Flatpak 应用数量（排除运行时与桌面环境自带包，不足 5 个则建议多用 Flatpak），并推荐 [harden-flatpak](https://github.com/lingyicute/harden-flatpak) 的 `lockdown.sh` + Flatseal；② uptime 超过一天提醒更新；③ 检测 2.4G 无线接收器（按键嗅探风险）；④ 检测 NTFS 分区 / Windows 安装（不可审计、可能污染 Linux 环境） |

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
flatpak run io.github.lingyicute.ComputeSec
```

### 本地构建

```bash
flatpak install flathub org.gnome.Platform//50 org.gnome.Sdk//50
flatpak-builder --user --install --force-clean build-dir io.github.lingyicute.ComputeSec.json
flatpak run io.github.lingyicute.ComputeSec
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
run.py                                   启动器（克隆运行 / Flatpak 内为 /app/bin/computesec）
computesec/
  ├── main.py        应用与窗口、导航、后台检测线程
  ├── ui.py          五个页面的构建
  ├── checks.py      数据采集与比对（fwupd、cmdline、sysctl、DMI、Flatpak、uptime、USB、NTFS）
  └── data.py        知识库：HSI 说明、内核参数、sysctl、厂商信誉
data/
  ├── io.github.lingyicute.ComputeSec.desktop
  ├── io.github.lingyicute.ComputeSec.metainfo.xml
  └── icons/hicolor/scalable/apps/io.github.lingyicute.ComputeSec.svg
io.github.lingyicute.ComputeSec.json     Flatpak 清单
.github/workflows/build.yml              CI：语法检查 + x86_64/aarch64 Flatpak 构建 + 打 tag 自动发布
```

## 注意事项

- 内核参数列表中的 `root=`、`rootflags=`、`rw`、`rhgb`、`quiet`、`vconsole.keymap` 等机器专属项不会被评估，请勿照搬他人的 `root=UUID=...`。
- 部分加固参数有副作用（例如 `module.sig_enforce=1` 会阻止 NVIDIA 私有驱动加载，`ia32_emulation=0` 会让 Steam/Wine 无法运行，`mitigations=auto,nosmt` 会关闭超线程），页面中已逐项标注 ⚠。建议先在 GRUB 菜单按 `e` 临时添加试运行一次。
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
