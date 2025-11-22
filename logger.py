# -*- coding: utf-8 -*-
"""
@desc: 该模块是异步日志管理器，用于将日志事件写入磁盘，而不会阻塞主程序的执行。
"""
import os
import json
import time
import threading
import queue
from typing import Optional


class LogManager:
    """
    一个异步日志记录器。

    它使用一个队列（`queue.Queue`）和一个后台工作线程来实现异步写入。
    主程序通过调用 `log_event` 将日志数据放入队列，然后可以立即继续执行其他任务。
    后台线程则负责从队列中取出数据，并将其写入对应的日志文件。
    这种设计避免了因磁盘I/O操作而导致的性能瓶颈，对于网络抓包等高吞吐量应用至关重要。
    """
    def __init__(self):
        """
        初始化LogManager。
        - `self.q`: 用于存储日志事件的线程安全队列。
        - `self._stop`: 一个 `threading.Event` 对象，用于通知后台线程停止工作。
        - `self._t`: 后台工作线程对象，初始化为None，在调用 `start()` 时才被创建（延迟初始化）。
        """
        self.q: "queue.Queue[dict]" = queue.Queue()
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None

    def start(self):
        """
        创建并启动后台工作线程。
        如果线程已经存在，则不会重复创建。
        """
        if self._t is None:
            self._t = threading.Thread(target=self._worker, daemon=True)
        self._t.start()

    def stop(self):
        """
        停止后台工作线程。
        通过设置停止事件并向队列中放入一个None作为哨兵值来优雅地终止线程。
        """
        self._stop.set()
        try:
            # 放入一个None值，以唤醒可能阻塞在 q.get() 的工作线程。
            self.q.put_nowait(None)
        except queue.Full:
            pass  # 如果队列已满，工作线程最终也会因为 _stop.is_set() 而退出。
        if self._t and self._t.is_alive():
            try:
                # 等待线程结束，设置一个短暂的超时以避免永久阻塞。
                self._t.join(timeout=2.0)
            except Exception:
                pass

    def log_event(self, data: dict):
        """
        将一个日志事件（字典）放入队列中，供后台线程处理。
        这是一个非阻塞操作。

        Args:
            data (dict): 要记录的日志数据，通常是一个包含时间戳、IP等信息的字典。
        """
        try:
            self.q.put(data)
        except Exception:
            # 在高负载下，如果队列已满，可能会抛出异常，这里选择忽略以避免主程序崩溃。
            pass

    def _ensure_dir(self, date_str: str) -> str:
        """
        确保日志目录存在。
        日志文件存储在 `./logs/<YYYY-MM-DD>/` 格式的目录中。

        Args:
            date_str (str): "YYYY-MM-DD" 格式的日期字符串。

        Returns:
            str: 确保存在的目录路径。
        """
        root = os.path.join(os.getcwd(), "logs")
        path = os.path.join(root, date_str)
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            # 处理并发创建目录时可能发生的错误。
            pass
        return path

    def _worker(self):
        """
        后台工作线程的主循环。
        它会持续从队列中获取日志事件并将其写入文件，直到收到停止信号。
        """
        while not self._stop.is_set():
            try:
                # 阻塞式地从队列中获取一个项目，直到有项目可用。
                item = self.q.get()
                # 如果获取到哨兵值None，则退出循环。
                if item is None:
                    break

                # -- 开始处理日志写入 --
                ts = item.get("timestamp") or time.time()
                date_str = time.strftime("%Y-%m-%d", time.localtime(ts))
                ip = item.get("ip") or "unknown"

                # 确保日志目录存在，并构建日志文件的完整路径。
                folder = self._ensure_dir(date_str)
                fp = os.path.join(folder, f"{ip}.log")

                # 将日志数据转换为JSON字符串。
                line = json.dumps(item, ensure_ascii=False)

                # 以追加模式打开文件并写入日志。
                with open(fp, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                # 捕获所有潜在的异常（如磁盘满、权限问题等），避免工作线程崩溃。
                pass
