# TERASim. GNU Make on Windows (w64devkit sh) or POSIX.
#   make build     — собрать workspace, tera-launcher.exe в корне
#   make arbiter   — собрать и запустить логин-сервер :7801, билеты :17802
#   make launcher  — собрать tera-launcher.exe в корень и запустить
#   make serve     — arbiter в фоне, лог в arbiter.log
#   make run       — serve, затем launcher; по выходу arbiter останавливается
#   make stop      — остановить arbiter, поднятый через make serve / make run

SHELL := sh
.DEFAULT_GOAL := help

ROOT     := $(subst \,/,$(CURDIR))
BIN      := $(ROOT)/target/debug
LAUNCHER := $(ROOT)/tera-launcher.exe
STOP_CMD = powershell.exe -NoProfile -Command '$$exe = [IO.Path]::GetFullPath("$(BIN)/tera-arbiter.exe"); if (Test-Path "$(ROOT)/.arbiter.pid") { $$id = [IO.File]::ReadAllText("$(ROOT)/.arbiter.pid").Trim(); if ($$id) { Stop-Process -Id $$id -Force -ErrorAction SilentlyContinue }; Remove-Item "$(ROOT)/.arbiter.pid" -Force -ErrorAction SilentlyContinue }; Get-Process -ErrorAction SilentlyContinue | Where-Object { $$_.ProcessName -eq "tera-arbiter" -and $$_.Path -and ([IO.Path]::GetFullPath($$_.Path) -eq $$exe) } | Stop-Process -Force -ErrorAction SilentlyContinue; exit 0'

.PHONY: help build release serve run stop arbiter launcher clean

help:
	@echo "make build      собрать workspace, tera-launcher.exe в корне"
	@echo "make arbiter    собрать и запустить логин-сервер :7801 и билеты :17802"
	@echo "make launcher   собрать tera-launcher.exe в корень и запустить"
	@echo "make serve      тот же сервер в фоне (лог: arbiter.log)"
	@echo "make run        serve, затем launcher; по выходу — stop"
	@echo "make stop       остановить tera-arbiter этого репозитория"
	@echo "make release    release-сборка, tera-launcher.exe в корне"
	@echo "make clean      cargo clean и tera-launcher.exe"

build:
	cargo build --workspace
	cp -f "$(BIN)/tera-launcher.exe" "$(LAUNCHER)"

release:
	cargo build --workspace --release
	cp -f "$(ROOT)/target/release/tera-launcher.exe" "$(LAUNCHER)"

arbiter:
	@$(STOP_CMD)
	cargo run -p tera-arbiter

launcher:
	cargo build -p tera-launcher
	cp -f "$(BIN)/tera-launcher.exe" "$(LAUNCHER)"
	"$(LAUNCHER)"

serve:
	@echo "arbiter -> 127.0.0.1:7801, tickets -> http://127.0.0.1:17802"
	@$(STOP_CMD)
	cargo build -p tera-arbiter
	@powershell.exe -NoProfile -Command '$$ErrorActionPreference = "Stop"; $$p = Start-Process -FilePath "$(BIN)/tera-arbiter.exe" -WorkingDirectory "$(ROOT)" -RedirectStandardOutput "$(ROOT)/arbiter.log" -RedirectStandardError "$(ROOT)/arbiter.err.log" -PassThru; [IO.File]::WriteAllText("$(ROOT)/.arbiter.pid", "$$($$p.Id)", [Text.Encoding]::ASCII)'
	@powershell.exe -NoProfile -Command '$$ok = $$false; for ($$i = 0; $$i -lt 50; $$i++) { $$up = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object { $$_.Port -eq 17802 }; if ($$up) { $$ok = $$true; break }; Start-Sleep -Milliseconds 100 }; if (-not $$ok) { Write-Error "arbiter did not listen on 17802; see arbiter.err.log"; exit 1 }'

run: serve
	@echo "launcher -> $(ROOT)/launcher/launcher.json"
	cargo build -p tera-launcher
	cp -f "$(BIN)/tera-launcher.exe" "$(LAUNCHER)"
	@set +e; \
	trap 'powershell.exe -NoProfile -Command '\''if (Test-Path "$(ROOT)/.arbiter.pid") { $$id = [IO.File]::ReadAllText("$(ROOT)/.arbiter.pid").Trim(); if ($$id) { Stop-Process -Id $$id -Force -ErrorAction SilentlyContinue }; Remove-Item "$(ROOT)/.arbiter.pid" -Force -ErrorAction SilentlyContinue }'\''' EXIT INT TERM; \
	"$(LAUNCHER)"; \
	status=$$?; \
	exit $$status

stop:
	@$(STOP_CMD)

clean:
	cargo clean
	rm -f .arbiter.pid arbiter.log arbiter.err.log "$(LAUNCHER)"
