# SIEM Endpoint Agent

Agent ini berjalan di VM endpoint Linux untuk membaca log, memonitor perubahan file, memeriksa status service, lalu mengirim event JSON ke SIEM server.

## Endpoint Default

- URL: `http://<IP_SIEM_SERVER>/api/events`
- Method: `POST`
- Content-Type: `application/json`

## Instalasi di VM Endpoint

```bash
git clone <URL_REPOSITORY_AGENT>
cd <NAMA_FOLDER_REPOSITORY>
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Menjalankan Agent

Jalankan dengan akses root/sudo agar bisa membaca `/var/log/auth.log` dan `/var/log/syslog`.

```bash
sudo .venv/bin/python agent.py
```

Contoh konfigurasi custom:

```bash
sudo .venv/bin/python agent.py \
  --server-url http://192.168.8.220:5000/api/events \
  --log-files /var/log/auth.log,/var/log/syslog \
  --watch-dirs /tmp/siem-watch,/etc/siem-test \
  --services ssh,cron \
  --custom-log /tmp/custom-app.log \
  --interval 5
```

Konfigurasi juga bisa memakai environment variable:

- `SIEM_SERVER_URL`
- `SIEM_LOG_FILES`
- `SIEM_WATCH_DIRS`
- `SIEM_SERVICES`
- `SIEM_CUSTOM_LOG`
- `SIEM_INTERVAL`

## Struktur Kode

- `agent.py`: entrypoint utama agar agent tetap bisa dijalankan dengan `python agent.py`.
- `siem_agent/app.py`: menjalankan thread sender, log watcher, file watcher, dan service watcher.
- `siem_agent/config.py`: konfigurasi CLI, environment variable, dan default endpoint SIEM.
- `siem_agent/events.py`: pembuatan format event JSON standar.
- `siem_agent/classifier.py`: klasifikasi baris log menjadi tipe event keamanan.
- `siem_agent/sender.py`: pengiriman event ke server SIEM via HTTP POST.
- `siem_agent/log_watcher.py`: monitoring penambahan baris pada file log.
- `siem_agent/file_watcher.py`: monitoring file created, modified, dan deleted.
- `siem_agent/service_watcher.py`: monitoring perubahan status service systemd.

## Format Event JSON

Agent mengirim field berikut:

```json
{
  "timestamp": "2026-06-17T10:00:00+00:00",
  "agent_id": "endpoint-host-root",
  "hostname": "endpoint-host",
  "source_ip": "192.168.8.x",
  "event_type": "failed_ssh_login",
  "severity": "medium",
  "source": "/var/log/auth.log",
  "message": "raw log atau deskripsi event",
  "raw_log": "isi baris log jika berasal dari file log"
}
```

## Event yang Didukung

- `failed_ssh_login`
- `successful_ssh_login`
- `failed_sudo`
- `user_created`
- `user_deleted`
- `package_installed`
- `service_started`
- `service_stopped`
- `file_created`
- `file_modified`
- `file_deleted`
- `service_or_custom_log`

## Skenario Pengujian

Failed SSH login:

```bash
ssh user_salah@IP_ENDPOINT
```

Successful SSH login:

```bash
ssh user_valid@IP_ENDPOINT
```

Failed sudo attempt:

```bash
sudo -k
sudo ls /root
```

User account creation/deletion:

```bash
sudo useradd siemtest
sudo userdel siemtest
```

Package installation:

```bash
sudo apt update
sudo apt install tree
```

Service stop/start:

```bash
sudo systemctl stop ssh
sudo systemctl start ssh
```

File operation:

```bash
mkdir -p /tmp/siem-watch
echo test > /tmp/siem-watch/a.txt
echo update >> /tmp/siem-watch/a.txt
rm /tmp/siem-watch/a.txt
```

Custom application log:

```bash
touch /tmp/custom-app.log
sudo .venv/bin/python agent.py --custom-log /tmp/custom-app.log
echo "custom app failed login from 10.10.10.10" >> /tmp/custom-app.log
```

## Catatan Integrasi

Jika SIEM server memakai nama field berbeda, sesuaikan fungsi `create_event()` di `siem_agent/events.py` agar field JSON cocok dengan database/API server.
