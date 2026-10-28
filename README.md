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

## 为什么做这个？

为了让安全加固不再有距离感。

对没有技术背景的普通用户来说，「安全加固」往往是个遥远的概念：绝大多数专业的安全建议，还没开始动手，就已经让人觉得无从下手了。于是梨做了这个小工具。

在 ComputeSec 里，安全建议是说人话的、可执行的（Actionable）。它不会对您说「您的 CPU 存在硅缺陷」——那只是无用的恐吓；它只会告诉您「您的 IOMMU 在 BIOS 里是关着的，现在重启去把它打开」——这才是安全工程。

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
  * 对于仅 root 可读的条目（`vm.mmap_rnd_bits` 等），通过「数据采集向导」由您粘贴 `sudo sysctl -a` 的结果补全；未提供时该项显示为「无法读取」并**不计入评分**。
  * 不在 Flatpak 里运行时，`/proc/sys` 的**实时读数优先**：您提供的快照只用来补上读不到的条目（补上的会标明这份快照是多久以前采的）。这样在您改动 sysctl 之后，结果不会停留在采快照那一刻。
  * 程序会根据您的当前架构，分别与内置 amd64 / aarch64 推荐 kargs 列表及 sysctl 加固列表进行对比。
* **版本线检查**：
  * 启动时会向 kernel.org 取一次当前 mainline / stable 的版本号。若您的内核既不属于 mainline，也不属于 stable（例如各 LTS 分支），程序会明确提醒：各 LTS 分支**均未包含**上游全部的安全修复与加固改进，本程序给出的 sysctl 与启动参数在这些旧内核上**不保证**能提供应有的加固效果（有的参数在旧内核上根本不存在，有的写进命令行后会被内核静默忽略，甚至因为出现在 `/proc/cmdline` 里被本程序误判为已加固）；这类版本线上的结论**不可作为安全加固的依据**，建议切换到 mainline 或 stable 内核。检查失败（离线、被防火墙拦截、Flatpak 权限被收回）时不会打扰您——「内核加固」页会显示一行
「未能核对」并给出重试按钮，主菜单里也可以手动重新检查。若本次连不上而又有一份过期缓存，
程序会照常给出结论，但会标明这些版本号是多久以前取得的。
* **三种"不计入评分"的情形**（都不会把分数拉低，也不代表已通过）：
  * **无法读取**：文件权限不足（如 `vm.mmap_rnd_bits` 为 `0600 root:root`）；
  * **未验证**：Flatpak 沙箱内的读数不可信（未共享宿主网络时，`net.*` 属于独立的网络命名空间；或您提供的快照中没有这一项），已忽略；
  * **疑似**：2.4G 无线接收器无法确认时只作提醒（见「使用习惯」）。
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
* **外设安全检测**：检测是否存在 2.4G 无线接收器，提示潜在的按键嗅探风险。能确认为 2.4G 接收器的直接扣分；只有厂商/型号高度重合、但无法确认是键鼠接收器时（例如型号里只写了 Receiver / Dongle）标为「疑似」，**只提醒、不扣分**，并给出自行确认的步骤。蓝牙适配器、红外接收器、电视棒等其它无线设备不参与判定。
* **环境隔离检测**：检测是否存在 NTFS / BitLocker 分区或 Windows 系统安装（提示不可审计、可能污染 Linux 环境）。
* **读不到就不计分**：本页任何一项如果因为权限或环境原因读不到（例如未安装 flatpak、没有 `/run/udev` 权限），会显示为「无法读取」并**不计入评分**，而不是按中间分处理——您无法通过任何操作改善它，扣分只会让总分失真。

## 方式一：Flatpak（推荐 ⭐）

> [!TIP]
> **为什么推荐用 Flatpak 运行？**
> 
> ComputeSec 自己也是一个软件，也有可能存在漏洞。国家级定向攻击者可能会攻击此软件，
> 进而在用户的电脑上执行代码。把此软件用 Flatpak 隔离起来、运行在沙箱之中，
> 可以起到纵深防御的作用——即使本软件被攻破，攻击者能造成的破坏也会受到沙箱的限制。

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
| `--system-talk-name=org.freedesktop.hostname1` | 通过 D-Bus 读取**宿主机**的发行版名称、内核版本与机型（沙箱内 `/etc/os-release` 是 runtime 的字段） |
| `--share=network` | 向 kernel.org 读取当前 mainline / stable 版本号，判断本机内核是否在受支持的版本线上；同时让沙箱内的 `/proc/sys/net` 就是宿主机的网络视图 |
| `--filesystem=/var/lib/flatpak:ro`、`~/.local/share/flatpak:ro` | 统计已安装的 Flatpak 应用 |
| `--filesystem=/run/udev:ro`、`/boot:ro`、`/efi:ro` | 检测 NTFS / BitLocker 分区与 Windows 引导器（`/boot:ro` 覆盖 `/boot/efi` 与 `/boot/EFI` 两种 ESP 挂载方式） |

`/proc/cmdline`、`/proc/sys`、`/sys/class/dmi`、`/sys/bus/usb` 在沙箱内默认可读，无需额外权限。

> **关于网络权限**：`--share=network` 只用于启动时向 kernel.org 读取 `releases.json`（版本号），
> 不上报任何信息，结果缓存 24 小时。您可以用 Flatseal 收回该权限：此时版本线检查会显示「未能核对」，
> 且由于沙箱内的 `net.*` 属于私有网络命名空间，程序不再采信这些读数——相关条目会显示为
> 「未验证」且不计入评分，其余检测不受影响。

> **从 v1.0.3 开始，本工具已不再请求 `--talk-name=org.freedesktop.Flatpak`。**
> 该权限允许通过 `flatpak-spawn --host` 在宿主机上以您的身份执行任意命令，等同于沙箱逃逸，
> 对一个只读检测工具来说过于侵入。需要更高权限才能获得的信息，改由「数据采集向导」引导您自己执行只读命令并粘贴结果。

### 数据采集向导

有一部分信息普通用户权限读不到，例如 `vm.mmap_rnd_bits` 与 `vm.mmap_rnd_compat_bits`
对应的 `/proc/sys` 文件权限是 `0600 root:root`；在 Flatpak 沙箱内还有更多条目不可见。

因此 ComputeSec 在启动时会弹出一个分步向导：

1. 每一步给出一条**只读命令**（如 `sudo sysctl -a`），可一键复制；
2. 您在自己的终端里执行并确认输出；
3. 复制输出后回到窗口点击「**我已复制结果**」——程序直接从剪贴板读取并解析，无需粘贴框。

采集结果只保存在 `~/.local/share/computesec/hostdata.json`，并记录 `boot_id`：
**重启后自动失效**（因为 sysctl 可能已改变），同一次开机内不会重复打扰您。
任何一步都可以跳过，跳过的项目会显示为「无法读取」且不计入评分（Flatpak 沙箱内另有
「未验证」状态：读数来自沙箱而非宿主机，同样不计入评分）；
随时可以从主菜单的「重新采集系统数据」（Ctrl+D）重新运行向导。

## 方式二：克隆直接运行

适合想随时跟进最新代码的开发者。请注意：此方式下程序直接以您的用户权限运行，**没有沙箱隔离**；日常使用请选择方式一。

依赖：Python ≥ 3.12、PyGObject、GTK 4、libadwaita ≥ 1.4（Fedora 39+ / Ubuntu 24.04+ / Debian 13+ / Arch），以及 `fwupd`（用于 HSI）。

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
python3 run.py --version     # 打印版本号（不需要图形环境）
python3 run.py --help        # 全部选项
```

也可以当作普通的 Python 包安装（会一并装出 `computesec` 命令、`.desktop`、metainfo 与图标）。
PyGObject、GTK 4 与 libadwaita 只能由发行版提供（无法用 pip 安装），仍需按上面的命令装好。
多数发行版不允许直接往系统 Python 里 `pip install`（PEP 668），请在虚拟环境里安装，
并加上 `--system-site-packages`，否则虚拟环境看不到发行版提供的 PyGObject：

```bash
python3 -m venv --system-site-packages ~/.venvs/computesec
~/.venvs/computesec/bin/pip install .
~/.venvs/computesec/bin/computesec --install   # 可选：把菜单项与图标装到 ~/.local/share
pip install -e ".[dev]"                        # 开发环境：额外装上 pytest / ruff / fonttools / brotli
```

`computesec` 命令与 `python3 run.py` 的选项完全相同。pip 装出的 `.desktop` 与图标位于虚拟环境的
`share/` 下，桌面环境不会去那里找，需要菜单项时请执行上面的 `computesec --install`。

## 项目结构

```
run.py                  启动器（克隆运行 / Flatpak 内为 /app/bin/computesec）
computesec/
  ├── cli.py            命令行参数与桌面集成（run.py 与 pip 装出的 computesec 命令共用，不依赖 gi）
  ├── main.py           应用与窗口、导航、后台检测线程
  ├── ui.py             五个页面的构建
  ├── checks.py         数据采集与比对（fwupd、cmdline、sysctl、DMI、Flatpak、uptime、USB、NTFS）
  ├── wizard.py         数据采集向导（分步执行只读命令 + 读取剪贴板）
  ├── hostdata.py       用户协助采集的数据：解析、校验、缓存（按 boot_id 失效）
  ├── kernelver.py      内核版本线检查（kernel.org 的 mainline / stable，缓存 24 小时）
  ├── hostinfo.py       宿主机身份信息（D-Bus org.freedesktop.hostname1）
  ├── xdg.py            XDG 数据目录（cli / hostdata / kernelver 共用）
  └── data.py           知识库：HSI 说明、内核参数、sysctl、厂商信誉
tests/                  单元测试（pytest，不依赖 GTK/D-Bus，运行：python -m pytest）
                        其中 test_ui_smoke.py 需要 PyGObject + 显示服务器，缺任一项自动跳过
pyproject.toml            打包元数据、pytest / ruff 工程配置
data/
  └── 图标和构建信息
uk._92li.lingyicute.ComputeSec.json       Flatpak 清单
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
