# QMusic Decryptor

QQ 音乐加密音频（`.mflac` / `.mgg`）解密工具。支持三类加密变体，算法移植自飞鼠格式（flyingmouse-format）的 mflac-format.js。

## 功能

- **QMC2 v1 / QTag**：旧版加密，密钥内嵌文件，完全离线解密
- **musicex**：新版加密，自动联网向 QQ 音乐换取密钥（仅上传歌曲 ID 与文件名，不上传音频内容）
- **批量解密**：文件夹递归扫描，一次处理整个目录
- **转 MP3**：解密后可转成 MP3（需要系统安装 ffmpeg）
- **分目录输出**：无损结果进 `output/`，MP3 结果进 `output_mp3/`

## 环境要求

- Python 3.8+
- `requests`（依赖清单见 `requirements.txt`）
- 转 MP3 需要 ffmpeg 可执行文件（在 PATH 中，或设置环境变量 `FLYINGMOUSE_FFMPEG_PATH`）

## 安装

```powershell
pip install -r requirements.txt
```

## 使用

### 批量解密（推荐）

把 QQ 音乐下载的加密歌曲放进 `testdata/` 文件夹，然后：

```powershell
python main.py                       # 解密全部歌曲，无损输出到 output/
python main.py testdata --mp3        # 解密并全部转成 MP3，输出到 output_mp3/
python main.py 其他文件夹             # 递归批量解密任意文件夹
```

### 单文件解密

```powershell
python main.py 歌曲.mflac                       # 输出到歌曲同目录
python main.py 歌曲.mflac -o 目标.flac          # 指定输出路径
python main.py 歌曲.mflac --mp3                 # 解密后转 MP3
```

### 单独转 MP3

```powershell
python flac2mp3.py 歌曲.flac                    # 输出同名 .mp3
python flac2mp3.py 歌曲.flac -o 目标.mp3 -b 320k
```

## Cookie 配置

musicex 新版加密必须联网换取密钥，需要 QQ 音乐登录凭据。修改项目内 [cookie.py](cookie.py) 的两行：

```python
UIN = "你的QQ数字ID"
QM_KEY = "登录cookie中的qm_keyst值"
```

获取方法：登录 y.qq.com → F12 → Network → 点任意请求 → Request Headers → Cookie，取 `uin=` 和 `qm_keyst=` 两项。

也可以用 `--cookie 文件路径` 指定其他 cookie 文件（支持 `.py` 或文本格式）。

## 目录结构

```
QMusic_decryptor/
├── main.py            # 入口（批量 / 单文件解密）
├── core.py            # 解密核心（QMC2 算法 / footer 解析 / musicex 联网）
├── flac2mp3.py        # 音频转 MP3 模块（可独立运行）
├── cookie.py          # QQ 音乐登录凭据（改两行即可）
├── requirements.txt   # Python 依赖清单
├── testdata/          # 批量输入：把下载的加密歌曲放这里
├── output/            # 批量输出：无损 / 原格式结果
└── output_mp3/        # 批量输出：MP3 结果
```

## 说明

- musicex 解密时若原音质档无权限，会自动降档尝试 FLAC 无损 → OGG 高音质 → MP3 320k
- 本工具只还原你账号有权限的内容，请勿用于获取无权限的付费内容
- 解密后的文件名与原名一致（含中文），仅扩展名变为实际格式（如 `坏女孩.mflac` → `坏女孩.flac`）；重复运行时自动追加序号不覆盖
