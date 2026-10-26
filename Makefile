# TERASim. GNU Make on Windows (w64devkit sh) or POSIX.
#   make build     — собрать launcher и arbiter
#   make arbiter   — логин-сервер :7801, билеты http://127.0.0.1:17802
#   make launcher  — клиент (arbiter уже должен слушать)
#   make serve     — arbiter в фоне, лог в arbiter.log
#   make run       — serve, затем launcher; по выходу arbiter останавливается
#   make stop      — остановить arbiter, поднятый через make serve / make run

SHELL := sh
.DEFAULT_GOAL := help

ROOT := $(subst \,/,$(CURDIR))
BIN  := $(ROOT)/target/debug
STOP_CMD = powershell.exe -NoProfile -Command '$$exe = [IO.Path]::GetFullPath("$(BIN)/tera-arbiter.exe"); if (Test-Path "$(ROOT)/.arbiter.pid") { $$id = [IO.File]::ReadAllText("$(ROOT)/.arbiter.pid").Trim(); if ($$id) { Stop-Process -Id $$id -Force -ErrorAction SilentlyContinue }; Remove-Item "$(ROOT)/.arbiter.pid" -Force -ErrorAction SilentlyContinue }; Get-Process tera-arbiter -ErrorAction SilentlyContinue | Where-Object { $$_.Path -and ([IO.Path]::GetFullPath($$_.Path) -eq $$exe) } | Stop-Process -Force -ErrorAction SilentlyContinue'

.PHONY: help build release serve run stop arbiter launcher clean

help:
	@echo "make build      собрать tera-launcher и tera-arbiter"
	@echo "make arbiter    логин-сервер 127.0.0.1:7801 и билеты :17802"
	@echo "make serve      тот же сервер в фоне (лог: arbiter.log)"
	@echo "make launcher   клиент TERA (сначала arbiter или serve)"
	@echo "make run        serve, затем launcher; по выходу — stop"
	@echo "make stop       остановить tera-arbiter этого репозитория"
	@echo "make release    release-сборка"
	@echo "make clean      cargo clean"

build:
	cargo build --workspace

release:
	cargo build --workspace --release

arbiter:
	cargo run -p tera-arbiter

launcher:
	cd launcher && cargo run -p tera-launcher

serve:
	@echo "arbiter -> 127.0.0.1:7801, tickets -> http://127.0.0.1:17802"
	@$(STOP_CMD)
	cargo build -p tera-arbiter
	@powershell.exe -NoProfile -Command '$$ErrorActionPreference = "Stop"; $$p = Start-Process -FilePath "$(BIN)/tera-arbiter.exe" -WorkingDirectory "$(ROOT)" -RedirectStandardOutput "$(ROOT)/arbiter.log" -RedirectStandardError "$(ROOT)/arbiter.err.log" -PassThru; [IO.File]::WriteAllText("$(ROOT)/.arbiter.pid", "$$($$p.Id)", [Text.Encoding]::ASCII)'
	@powershell.exe -NoProfile -Command '$$ok = $$false; for ($$i = 0; $$i -lt 50; $$i++) { $$up = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object { $$_.Port -eq 17802 }; if ($$up) { $$ok = $$true; break }; Start-Sleep -Milliseconds 100 }; if (-not $$ok) { Write-Error "arbiter did not listen on 17802; see arbiter.err.log"; exit 1 }'

run: serve
	@echo "launcher -> $(ROOT)/launcher/launcher.json"
	@set +e; \
	trap 'powershell.exe -NoProfile -Command '\''if (Test-Path "$(ROOT)/.arbiter.pid") { $$id = [IO.File]::ReadAllText("$(ROOT)/.arbiter.pid").Trim(); if ($$id) { Stop-Process -Id $$id -Force -ErrorAction SilentlyContinue }; Remove-Item "$(ROOT)/.arbiter.pid" -Force -ErrorAction SilentlyContinue }'\''' EXIT INT TERM; \
	cd launcher && "$(BIN)/tera-launcher.exe"; \
	status=$$?; \
	exit $$status

stop:
	@$(STOP_CMD)

clean:
	cargo clean
	rm -f .arbiter.pid arbiter.log arbiter.err.log
