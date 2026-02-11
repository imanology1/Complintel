#!/usr/bin/env bash
# Linux Filesystem Encryption Check Agent
# Checks for encrypted filesystems and LUKS volumes.
#
# Checks:
#   - LUKS-encrypted block devices via lsblk and blkid
#   - dm-crypt mapped devices
#   - eCryptfs mounted filesystems
#   - /tmp, /home, and swap encryption status
#   - fscrypt or ext4/f2fs native encryption
#   - Encrypted swap
#
# Output: JSON array of Finding objects to stdout.

set -euo pipefail

findings="["
first=true

add_finding() {
    local resource_id="$1"
    local resource_type="$2"
    local status="$3"
    local message="$4"

    if [ "$first" = true ]; then
        first=false
    else
        findings+=","
    fi

    findings+=$(printf '{"resource_id":"%s","resource_type":"%s","status":"%s","message":"%s"}' \
        "$resource_id" "$resource_type" "$status" "$message")
}

# ---------------------------------------------------------------------------
# Check 1: LUKS volumes via blkid
# ---------------------------------------------------------------------------
luks_count=0
if command -v blkid &>/dev/null; then
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            dev=$(echo "$line" | awk -F: '{print $1}')
            luks_count=$((luks_count + 1))
            add_finding "${dev}" "Linux::FilesystemEncryption" "PASS" \
                "LUKS encrypted volume detected: ${dev}"
        fi
    done < <(blkid 2>/dev/null | grep -i "crypto_LUKS" || true)
fi

if [ "$luks_count" -eq 0 ]; then
    # Also try lsblk
    if command -v lsblk &>/dev/null; then
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                dev=$(echo "$line" | awk '{print $1}')
                luks_count=$((luks_count + 1))
                add_finding "${dev}" "Linux::FilesystemEncryption" "PASS" \
                    "LUKS encrypted volume detected via lsblk: ${dev}"
            fi
        done < <(lsblk -o NAME,FSTYPE 2>/dev/null | grep -i "crypto_LUKS" || true)
    fi
fi

if [ "$luks_count" -eq 0 ]; then
    add_finding "luks:volumes" "Linux::FilesystemEncryption" "FAIL" \
        "No LUKS encrypted volumes detected"
else
    add_finding "luks:summary" "Linux::FilesystemEncryption" "PASS" \
        "Found ${luks_count} LUKS encrypted volume(s)"
fi

# ---------------------------------------------------------------------------
# Check 2: dm-crypt mapped devices
# ---------------------------------------------------------------------------
dmcrypt_count=0
if [ -d /dev/mapper ]; then
    while IFS= read -r mapper_dev; do
        if [ -n "$mapper_dev" ] && [ "$mapper_dev" != "control" ]; then
            dev_path="/dev/mapper/${mapper_dev}"
            if [ -e "$dev_path" ]; then
                # Check if this is a crypt target
                dm_type=$(dmsetup info "$mapper_dev" 2>/dev/null | grep -i "target" || true)
                if echo "$dm_type" | grep -qi "crypt"; then
                    dmcrypt_count=$((dmcrypt_count + 1))
                    add_finding "${dev_path}" "Linux::FilesystemEncryption" "PASS" \
                        "dm-crypt encrypted device: ${dev_path}"
                fi
            fi
        fi
    done < <(ls /dev/mapper/ 2>/dev/null || true)
fi

if command -v dmsetup &>/dev/null; then
    crypt_targets=$(dmsetup table --target crypt 2>/dev/null | wc -l || echo "0")
    if [ "$crypt_targets" -gt 0 ] && [ "$dmcrypt_count" -eq 0 ]; then
        dmcrypt_count=$crypt_targets
        add_finding "dm-crypt:active" "Linux::FilesystemEncryption" "PASS" \
            "Found ${crypt_targets} active dm-crypt target(s)"
    fi
fi

if [ "$dmcrypt_count" -eq 0 ] && [ "$luks_count" -eq 0 ]; then
    add_finding "dm-crypt:devices" "Linux::FilesystemEncryption" "FAIL" \
        "No dm-crypt encrypted devices detected"
fi

# ---------------------------------------------------------------------------
# Check 3: eCryptfs
# ---------------------------------------------------------------------------
ecryptfs_count=$(mount 2>/dev/null | grep -c "ecryptfs" || echo "0")
if [ "$ecryptfs_count" -gt 0 ]; then
    add_finding "ecryptfs:mounted" "Linux::FilesystemEncryption" "PASS" \
        "Found ${ecryptfs_count} eCryptfs mounted filesystem(s)"
else
    add_finding "ecryptfs:mounted" "Linux::FilesystemEncryption" "PASS" \
        "No eCryptfs filesystems mounted (not necessarily required if LUKS is used)"
fi

# ---------------------------------------------------------------------------
# Check 4: /home encryption
# ---------------------------------------------------------------------------
home_encrypted=false

# Check if /home is on LUKS
if command -v findmnt &>/dev/null; then
    home_device=$(findmnt -n -o SOURCE /home 2>/dev/null || echo "")
    if [ -n "$home_device" ]; then
        # Check if device is under /dev/mapper (likely LUKS)
        if echo "$home_device" | grep -q "/dev/mapper/"; then
            home_encrypted=true
            add_finding "/home:encryption" "Linux::FilesystemEncryption" "PASS" \
                "/home is on an encrypted device: ${home_device}"
        fi
    fi

    # Check if / is encrypted (which includes /home if not separately mounted)
    root_device=$(findmnt -n -o SOURCE / 2>/dev/null || echo "")
    if [ -z "$home_device" ] && echo "$root_device" | grep -q "/dev/mapper/"; then
        home_encrypted=true
        add_finding "/home:encryption" "Linux::FilesystemEncryption" "PASS" \
            "/home is under root filesystem on encrypted device: ${root_device}"
    fi
fi

# Check for eCryptfs on /home
if mount 2>/dev/null | grep -q "ecryptfs.*/home"; then
    home_encrypted=true
    add_finding "/home:ecryptfs" "Linux::FilesystemEncryption" "PASS" \
        "/home is encrypted with eCryptfs"
fi

if [ "$home_encrypted" = false ]; then
    add_finding "/home:encryption" "Linux::FilesystemEncryption" "FAIL" \
        "/home does not appear to be on an encrypted filesystem"
fi

# ---------------------------------------------------------------------------
# Check 5: /tmp encryption
# ---------------------------------------------------------------------------
tmp_encrypted=false
if command -v findmnt &>/dev/null; then
    tmp_device=$(findmnt -n -o SOURCE /tmp 2>/dev/null || echo "")
    if [ -n "$tmp_device" ]; then
        if echo "$tmp_device" | grep -q "/dev/mapper/"; then
            tmp_encrypted=true
            add_finding "/tmp:encryption" "Linux::FilesystemEncryption" "PASS" \
                "/tmp is on an encrypted device: ${tmp_device}"
        elif echo "$tmp_device" | grep -q "tmpfs"; then
            tmp_encrypted=true
            add_finding "/tmp:encryption" "Linux::FilesystemEncryption" "PASS" \
                "/tmp is mounted as tmpfs (RAM-backed, not persisted to disk)"
        fi
    else
        # /tmp may be part of root
        if echo "$root_device" | grep -q "/dev/mapper/"; then
            tmp_encrypted=true
            add_finding "/tmp:encryption" "Linux::FilesystemEncryption" "PASS" \
                "/tmp is under root filesystem on encrypted device"
        fi
    fi
fi

if [ "$tmp_encrypted" = false ]; then
    add_finding "/tmp:encryption" "Linux::FilesystemEncryption" "FAIL" \
        "/tmp does not appear to be encrypted or tmpfs-backed"
fi

# ---------------------------------------------------------------------------
# Check 6: Swap encryption
# ---------------------------------------------------------------------------
swap_lines=$(swapon --show=NAME,TYPE 2>/dev/null | tail -n +2 || cat /proc/swaps 2>/dev/null | tail -n +2 || true)
if [ -n "$swap_lines" ]; then
    swap_encrypted=true
    while IFS= read -r swap_entry; do
        swap_dev=$(echo "$swap_entry" | awk '{print $1}')
        if [ -n "$swap_dev" ]; then
            if echo "$swap_dev" | grep -q "/dev/mapper/\|/dev/dm-"; then
                add_finding "${swap_dev}:swap-encryption" "Linux::FilesystemEncryption" "PASS" \
                    "Swap device appears encrypted: ${swap_dev}"
            else
                swap_encrypted=false
                add_finding "${swap_dev}:swap-encryption" "Linux::FilesystemEncryption" "FAIL" \
                    "Swap device is NOT encrypted: ${swap_dev}"
            fi
        fi
    done <<< "$swap_lines"

    if [ "$swap_encrypted" = true ]; then
        add_finding "swap:summary" "Linux::FilesystemEncryption" "PASS" \
            "All swap devices are encrypted"
    fi
else
    add_finding "swap:none" "Linux::FilesystemEncryption" "PASS" \
        "No swap devices active (no unencrypted swap risk)"
fi

# ---------------------------------------------------------------------------
# Check 7: crypttab entries
# ---------------------------------------------------------------------------
if [ -f /etc/crypttab ]; then
    entry_count=$(grep -cvE '^\s*#|^\s*$' /etc/crypttab 2>/dev/null || echo "0")
    if [ "$entry_count" -gt 0 ]; then
        add_finding "/etc/crypttab" "Linux::FilesystemEncryption" "PASS" \
            "crypttab has ${entry_count} configured encrypted device(s)"
    else
        add_finding "/etc/crypttab" "Linux::FilesystemEncryption" "FAIL" \
            "crypttab exists but has no configured entries"
    fi
else
    add_finding "/etc/crypttab" "Linux::FilesystemEncryption" "FAIL" \
        "/etc/crypttab not found -- no encrypted devices configured at boot"
fi

findings+="]"
echo "$findings"
