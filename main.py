# -*- coding: utf-8 -*-
"""QMusic Decryptor 主入口：解密 QQ 音乐 mflac/mgg 加密音频。

用法：
  python main.py                             # 批量解密 testdata，无损输出到 output/、MP3 输出到 output_mp3/
  python main.py <文件夹>                    # 递归批量解密指定文件夹
  python main.py <文件.mflac|.mgg>           # 单文件解密
  python main.py <输入> [-o 输出] [-m|--mp3] [--cookie cookie.py]

解密核心在 core.py（QMC2 v1 / QTag / musicex 三类加密变体）。
"""

import argparse
import sys
from pathlib import Path

from core import (DEFAULT_INPUT_DIR, DEFAULT_MP3_DIR, DEFAULT_OUTPUT_DIR,
                  MFLAC_EXTS, QmcError, collect_audio_files, convert_mflac)
from flac2mp3 import Mp3Error, convert_to_mp3

# stdout 行缓冲 + UTF-8
sys.stdout.reconfigure(line_buffering=True, encoding="utf-8")


def unique_path(path):
    """路径已存在时自动追加序号，避免覆盖。"""
    if not path.exists():
        return path
    for i in range(1, 10000):
        cand = path.with_name(f"{path.stem}_{i}{path.suffix}")
        if not cand.exists():
            return cand
    return path


def build_parser():
    parser = argparse.ArgumentParser(
        description="解密 QQ 音乐 mflac/mgg 加密音频（QMC2 v1 / QTag / musicex）。")
    parser.add_argument("input", nargs="?", default=None,
                        help="输入文件或文件夹（默认批量处理项目内 testdata 文件夹）")
    parser.add_argument("-o", "--output",
                        help="单文件时为输出文件路径；批量时为输出文件夹（默认项目根目录 output/）")
    parser.add_argument("-m", "--mp3", action="store_true",
                        help="解密后转成 MP3（需要系统安装 ffmpeg）")
    parser.add_argument("--cookie", help="自定义 cookie 文件路径（默认自动读项目内 cookie.py）")
    return parser


def run_single(args, input_path):
    try:
        audio, fmt = convert_mflac(str(input_path), cookie_path=args.cookie)
    except QmcError as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"错误：读取文件失败：{e}", file=sys.stderr)
        return 2

    if args.output:
        out_path = Path(args.output)
    elif args.mp3:
        out_path = input_path.with_name(f"{input_path.stem}.mp3")
    else:
        out_path = input_path.with_name(f"{input_path.stem}.{fmt}")

    try:
        if args.mp3 and fmt != "mp3":
            convert_to_mp3(audio, fmt, out_path)
            print(f"解密并转 MP3 成功：{out_path}（原格式：{fmt.upper()}）")
        else:
            out_path.write_bytes(audio)
            if args.mp3:
                print(f"解密成功：{out_path}（本来就是 MP3，无需转换）")
            else:
                print(f"解密成功：{out_path}（格式：{fmt.upper()}）")
    except Mp3Error as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2
    except QmcError as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"错误：写入输出失败：{e}", file=sys.stderr)
        return 2
    return 0


def run_batch(args, src_dir):
    files = collect_audio_files(src_dir)
    if not files:
        print(f"在 {src_dir} 下未找到任何加密文件（{', '.join(sorted(MFLAC_EXTS))}）。")
        return 2
    if args.output:
        out_dir = Path(args.output)
    elif args.mp3:
        out_dir = DEFAULT_MP3_DIR
    else:
        out_dir = DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    ok, failed = [], []
    for f in files:
        try:
            audio, fmt = convert_mflac(str(f), cookie_path=args.cookie)
            if args.mp3 and fmt != "mp3":
                out_path = unique_path(out_dir / f"{f.stem}.mp3")
                convert_to_mp3(audio, fmt, out_path)
            else:
                suffix = ".mp3" if args.mp3 else f".{fmt}"
                out_path = unique_path(out_dir / f"{f.stem}{suffix}")
                out_path.write_bytes(audio)
            ok.append((f.name, out_path))
            print(f"  ✓ {f.name} → {out_path}")
        except Mp3Error as e:
            failed.append((f.name, str(e)))
            print(f"  ✗ {f.name}：{e}", file=sys.stderr)
        except QmcError as e:
            failed.append((f.name, str(e)))
            print(f"  ✗ {f.name}：{e}", file=sys.stderr)
        except OSError as e:
            failed.append((f.name, str(e)))
            print(f"  ✗ {f.name}：{e}", file=sys.stderr)

    print(f"\n批量完成：成功 {len(ok)}，失败 {len(failed)}，输出目录：{out_dir}")
    return 0 if not failed else 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.input:
        input_path = Path(args.input)
        if input_path.is_dir():
            return run_batch(args, input_path)
        return run_single(args, input_path)
    # 无参数：默认批量处理项目内 testdata 文件夹
    return run_batch(args, DEFAULT_INPUT_DIR)


if __name__ == "__main__":
    sys.exit(main())
