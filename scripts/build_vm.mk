# ======================
# VM Provisioning Module
# ======================
#
# A makefile fragment for creating a VM. 
#
# Simply include this file setting any of the following variables:
#
#  VM_NAME     : name for virtsh and hostname (default alpine-vm)
#  VM_RESIZE   : qemu-img resize plus (default 100M)
#  VM_RAM      : virt-install --ram (default 512)
#  VM_CPUS     : virt-install --vcpus (default 1)
#  VM_GRAPHICS : virt-install --graphics (default none)
#  VM_CONSOLE  : virt-install --console (default pty,target_type=serial)
#  VM_REBOOT   : wait for vm to reboot/poweroff after first install
#
# Example
# -------
#  VM_NAME = test-vm
#  include scripts/build_vm.mk
#  build-vm: vm-create
#      @echo "VM $(VM_NAME) is ready."
#
# Targets
# -------
# vm-create  : create/start vm
# vm-start   : start-vm
# vm-list    : show VM domain info (dominfo, domifaddr)
# vm-config  : show VM config
# vm-clean   : delete VM
#
# Design
# ------
# - Downloads an alpine VM disk image using wget
# - Resizes disk image using qemu-img
# - Uses a cloud-config user-data.yaml template file to configure VM
# - Injects SSH public key into cloud-config file for passwordless VM access
# - Runs to virt-install to create VM
# - Uses virsh to manage VM
# - VM can be accessed via ssh key or alpine:alpine or console root:alpine 
# - ssh directly to VM with ssh alpine@VM_NAME if nsswitch.conf allows it 
# - Add libvirt_guest to hosts line in /etc/nsswitch.conf e.g "hosts: files libvirt_guest"
#
# Dependencies
# ------------
# - wget         : download disk image
# - qemu-img     : resize disk image
# - virt-install : create vm
# - virsh        : vm management
# 

# whats our location
SCRIPT_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

# defaults
VM_NAME ?= alpine-vm
VM_RESIZE ?= 100M
VM_RAM ?= 512
VM_CPUS ?= 1
VM_CONSOLE ?= pty,target_type=serial
VM_GRAPHICS ?= none

# helpers
VM_GET_IP = virsh -q domifaddr $(VM_NAME) --source lease | awk '{print $$4}' | cut -d/ -f1
VM_USER := alpine
VM_HOME := /home/$(VM_USER)
VM_BIN_DIR := /home/$(VM_USER)/bin

# boot time
VM_WAIT_RETRIES = 30
VM_WAIT_SLEEP   = 3
VM_WAIT_TIMEOUT = $(shell expr $(VM_WAIT_RETRIES) \* $(VM_WAIT_SLEEP))

# alpine linux image file
# -----------------------
OS_VARIANT= alpinelinux3.21
OS_NAME=alpine
REL_VER= 3.21
PATCH_VER=.6
REL_NAME = $(OS_NAME)-$(REL_VER)$(PATCH_VER)
REL_FILE = nocloud_$(REL_NAME)-x86_64-bios-cloudinit-r0.qcow2
REL_DIR = v$(REL_VER)/releases/cloud
MIRROR = https://dl-cdn.alpinelinux.org
REL_URL = $(MIRROR)/$(REL_DIR)/$(REL_FILE)

# our vm
# ------
VM_FILE := $(VM_NAME).qcow2
VM_DIR  := vmdir

# where we store downloads
# ------------------------
ifeq ($(origin VM_CACHE_DIR), undefined)
  VM_CACHE_DIR := $(shell echo $${XDG_CACHE_HOME:-$$HOME/.cache}/my-vm-project)
endif

VM_CACHE_FILE = $(VM_CACHE_DIR)/$(REL_FILE)
VM_DISK = $(VM_DIR)/$(VM_FILE)

# autoconfigure using user-data.yaml
# ---------------------------------
VM_USER_DATA = $(BUILD_DIR)/user-data.yaml
VM_META_DATA = $(BUILD_DIR)/meta-data
VM_DONE      = $(BUILD_DIR)/.vm_done


# get public key
# --------------
VM_SSH_KEYFILE := ~/.ssh/id_rsa
VM_PUB_KEYFILE := $(VM_SSH_KEYFILE).pub
VM_SSH_PUBKEY  := $(shell cat $(VM_PUB_KEYFILE) 2>/dev/null || echo "NO_KEY_FOUND")

# allow ssh be run without user input
VM_SSH_OPTS = \
	-o StrictHostKeyChecking=no \
	-o UserKnownHostsFile=/dev/null \
	-o LogLevel=ERROR \
	-o IdentitiesOnly=yes -i $(VM_SSH_KEYFILE)
ifeq ($(V),1)
  VM_SSH_OPTS += -v
endif

# user-data template file
# -----------------------
USER_DATA_TEMPLATE := $(SCRIPT_DIR)user-data.yaml

# create cloud-init user-data
# ---------------------------
$(VM_USER_DATA): $(USER_DATA_TEMPLATE) | $(BUILD_DIR)
	$(Q)if [ "$(VM_SSH_PUBKEY)" = "NO_KEY_FOUND" ]; then \
		echo "Error: No public key found in ~/.ssh/id_rsa.pub"; \
		exit 1; \
	fi
	$(Q)sed -e "s|{{VM_NAME}}|$(VM_NAME)|g" \
	        -e "s|{{SSH_PUBLIC_KEY}}|$(VM_SSH_PUBKEY)|g" \
	        $< > $@

# create meta-data
# ----------------
$(VM_META_DATA): | $(BUILD_DIR) 
	$(Q)echo "instance-id: $$(date +%s)" > $(VM_META_DATA)
	$(Q)echo "local-hostname: $(VM_NAME)" >> $(VM_META_DATA)

$(VM_CACHE_DIR):
	$(Q)mkdir -p $@

$(VM_DIR):
	$(Q)mkdir -p $@

# download image file
# -------------------
$(VM_CACHE_FILE) : | $(VM_CACHE_DIR)
	$(Q)echo "[+] Downloading VM-DISK: $(REL_URL)"
	$(Q)wget -nv --no-verbose --show-progress -O $@.tmp $(REL_URL)
	$(Q)mv $@.tmp $@
	$(Q)chmod 444 $@

# copy disk image, rename and resize
# ----------------------------------
$(VM_DISK): | $(VM_CACHE_FILE) $(VM_DIR)
	$(Q)echo "[+] Creating VM-DISK: $@"
	$(Q)cp $(VM_CACHE_FILE) $@
	$(Q)chmod 644 $@
	$(Q)qemu-img resize -q $@ +$(VM_RESIZE)
	$(Q)chmod 444 $@

.PHONY: vm-config
vm-config:
	@echo "-------SRC_IMAGE------------"
	@echo "OS_NAME=$(OS_NAME)"
	@echo "OS_VARIANT=$(OS_VARIANT)"
	@echo "REL_NAME=$(REL_NAME)"
	@echo "REL_FILE=$(REL_FILE)"
	@echo "REL_VER=$(REL_VER)"
	@echo "MIRROR=$(MIRROR)"
	@echo "REL_URL=$(REL_URL)"
	@echo "------INSTALL_IMAGE------------"
	@echo "CACHE_DIR=$(VM_CACHE_DIR)"
	@echo "VM_BASE_IMAGE=$(VM_CACHE_FILE)"
	@echo "VM_RUN_IMAGE=$(VM_DISK)"
	@echo "VM_USER_DATA=$(VM_USER_DATA)"
	@echo "VM_META_DATA=$(VM_META_DATA)"
	@echo "VM_PUB_KEYFILE=$(VM_PUB_KEYFILE)"

.PHONY:vm-cache
vm-cache:
	ls -lh $(VM_CACHE_DIR)

# install vm image
# ----------------
.PHONY:vm-install
vm-install: $(VM_DISK) $(VM_USER_DATA) $(VM_META_DATA)
	$(Q)echo "[+] Installing VM: $(VM_NAME)"
	$(Q)virt-install \
	--quiet \
	--noautoconsole \
	--boot hd,menu=off \
	--cloud-init user-data=$(VM_USER_DATA),meta-data=$(VM_META_DATA) \
	--name $(VM_NAME) \
	--virt-type kvm \
	--ram $(VM_RAM) \
	--vcpus $(VM_CPUS) \
	--graphics $(VM_GRAPHICS) \
	--console $(VM_CONSOLE) \
	--disk path=$(VM_DISK),format=qcow2,bus=virtio \
	--network network=default,model=virtio \
	--os-variant $(OS_VARIANT) \
	--rng /dev/urandom \
	--import
	$(Q)echo "[+] Started VM: $(VM_NAME)"

# wait for vm poweroff (after first install)
# --------------------
.PHONY:vm-poweroff
vm-poweroff:
	$(Q)[ "$(VM_REBOOT)" != "1" ] && exit 0; \
	echo "[+] Waiting for $(VM_NAME) poweroff"; \
	@count=0; \
	while [ $$count -lt $(VM_WAIT_RETRIES) ]; do \
		if ! virsh list --name | grep -q "^$(VM_NAME)$$"; then \
			echo "VM shutdown after $$((count * $(VM_WAIT_SLEEP)))s."; \
			exit 0; \
		fi; \
		count=$$((count + 1)); \
		sleep $(VM_WAIT_SLEEP); \
		echo " ... still waiting ($$count/$(VM_WAIT_RETRIES))"; \
	done; \
	echo " [ERROR] VM failed to power off after $(VM_WAIT_TIMEOUT) seconds"; \
	exit 1
	
# ensure vm exists
# ----------------
$(VM_DONE): | $(BUILD_DIR)
	$(Q)virsh -q dominfo $(VM_NAME) >/dev/null 2>&1 || $(MAKE) vm-install vm-poweroff
	$(Q)touch $@

.PHONY:vm-create
vm-create: $(VM_DONE)
	@$(MAKE) vm-start

.PHONY: vm-start
vm-start:
	$(Q)virsh -q list --state-running --name | grep -q "^$(VM_NAME)" || \
		(echo "[+] Starting VM: $(VM_NAME)" && virsh -q start $(VM_NAME))
	$(Q)$(MAKE) vm-wait

# wait for ssh access
# -------------------
.PHONY:vm-wait
vm-wait:
	$(Q)echo "[+] Waiting for VM $(VM_NAME) to reach SSH"
	@count=0; \
	while [ $$count -lt $(VM_WAIT_RETRIES) ]; do \
		VM_IP=$$(virsh -q domifaddr $(VM_NAME) --source lease | awk '{print $$4}' | cut -d/ -f1); \
		if [ -n "$$VM_IP" ] && nc -z -w 2 $$VM_IP 22 >/dev/null 2>&1; then \
			echo " => VM is UP at $$VM_IP."; \
			exit 0; \
		fi; \
		sleep $(VM_WAIT_SLEEP); \
		count=$$((count + 1)); \
		echo " ... still waiting ($$count/$(VM_WAIT_RETRIES))"; \
	done; \
	echo " [ERROR] VM failed to reach SSH after $(VM_WAIT_TIMEOUT) seconds"; \
	exit 1

.PHONY: vm-list
vm-list:
	@echo "[+] Checking VM $(VM_NAME)"
	$(Q)virsh -q dominfo $(VM_NAME)   2>/dev/null || echo " => VM not found"
	$(Q)virsh -q domifaddr $(VM_NAME) 2>/dev/null || true

vm-clean:
	 virsh -q destroy $(VM_NAME) || true
	 virsh -q undefine $(VM_NAME) || true || true
	 rm -rf $(VM_DIR) $(VM_DONE) $(VM_USER_DATA)
