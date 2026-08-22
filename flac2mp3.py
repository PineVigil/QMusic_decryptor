# -*- coding: utf-8 -*-
"""FLAC/OGG 等音频 → MP3 转换工具（基于系统 ffmpeg）。

作为独立脚本：
  python flac2mp3.py 输入.flac [-o 输出.mp3] [-b 320k]

作为模块被 main.py 引用：
  from flac2mp3 import convert_to_mp3
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


class Mp3Error(Exception):
    """转 MP3 相关错误。"""


def find_ffmpeg():
    """返回 ffmpeg 可执行路径：FLYINGMOUSE_FFMPEG_PATH 环境变量 > PATH。"""
    env = os.environ.get("FLYINGMOUSE_FFMPEG_PATH")
    if env:
        return env
    return shutil.which("ffmpeg")


def convert_to_mp3(audio, source_fmt, output_path, bitrate="320k"):
    """把音频字节转成 MP3 写入 output_path（供解密程序调用）。"""
    ffmpeg = find_ffmpeg()
    if not ffmpeg:
        raise Mp3Error(
            "未找到 ffmpeg，无法转 MP3；请安装 ffmpeg 并加入 PATH，"
            "或设置环境变量 FLYINGMOUSE_FFMPEG_PATH。")
    output_path = Path(output_path)
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / f"in.{source_fmt}"
        src.write_bytes(audio)
        cmd = [ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
               "-i", str(src), "-codec:a", "libmp3lame", "-b:a", bitrate,
               str(output_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise Mp3Error(f"转 MP3 失败：{result.stderr.strip()}")
    return output_path


def convert_file_to_mp3(input_path, output_path=None, bitrate="320k"):
    """文件 → 文件转换；output_path 缺省时与输入同目录同名 .mp3。"""
    input_path = Path(input_path)
    if not input_path.is_file():
        raise Mp3Error(f"输入文件不存在：{input_path}")
    output_path = Path(output_path) if output_path else input_path.with_suffix(".mp3")
    if str(output_path).lower() == str(input_path).lower():
        raise Mp3Error("输出路径不能与输入相同。")
    return convert_to_mp3(
        input_path.read_bytes(), input_path.suffix.lstrip(".") or "flac",
        output_path, bitrate)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="把 FLAC/OGG 等音频转成 MP3（需要系统安装 ffmpeg）。")
    parser.add_argument("input", help="输入音频文件（.flac / .ogg / .wav 等）")
    parser.add_argument("-o", "--output", help="输出 MP3 路径（默认与输入同目录同名 .mp3）")
    parser.add_argument("-b", "--bitrate", default="320k", help="MP3 码率，默认 320k")
    args = parser.parse_args(argv)

    try:
        out = convert_file_to_mp3(args.input, args.output, args.bitrate)
    except Mp3Error as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2
    print(f"转 MP3 成功：{out}（码率 {args.bitrate}）")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True, encoding="utf-8")
    sys.exit(main())
