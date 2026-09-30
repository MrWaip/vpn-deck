import {
  ButtonItem,
  DialogBody,
  DialogButton,
  DialogFooter,
  DialogHeader,
  ModalRoot,
  PanelSection,
  PanelSectionRow,
  showModal,
  staticClasses,
  TextField,
  ToggleField,
} from "@decky/ui";
import {
  call,
  callable,
  definePlugin,
  FileSelectionType,
  openFilePicker,
  toaster,
} from "@decky/api";
import { useState, useEffect, useCallback, useRef } from "react";
import { FaNetworkWired } from "react-icons/fa";

interface VPNError {
  timestamp: number;
  operation: string;
  error_type: string;
  message: string;
  details: Record<string, any>;
}

interface ConfigInfo {
  name: string;
  interface: string;
  active: boolean;
  managed_by: string;
  type: "awg" | "sing-box" | "vless";
  protocol: string;
}

interface VPNOpResult {
  success: boolean;
  error: string | null;
  interface: string;
  switched_from?: string[];
}

interface TunnelStatus {
  name: string;
  interface: string;
  type: string;
  address: string | null;
  handshake_age: number | null;
  exit_ip: string | null;
  exit_country: string;
  rx_bytes: number | null;
  tx_bytes: number | null;
  sampled_at: number;
}

interface TunnelRate {
  rx: number;
  tx: number;
}

interface PluginSettings {
  restore_on_boot: boolean;
}

const listConfigsWithStatus = callable<[], ConfigInfo[]>(
  "list_configs_with_status",
);
const vpnStartConfig = callable<[{ config_name: string }], VPNOpResult>(
  "vpn_start_config",
);
const vpnStopConfig = callable<[{ config_name: string }], VPNOpResult>(
  "vpn_stop_config",
);
const getErrors = callable<[], VPNError[]>("get_errors");
const connectionStatus = callable<[], TunnelStatus[]>("connection_status");
const getSettings = callable<[], PluginSettings>("get_settings");
const setRestoreOnBoot = callable<[{ enabled: boolean }], PluginSettings>("set_restore_on_boot");
const clearErrors = callable<[], boolean>("clear_errors");

interface DeleteConfigResult {
  success: boolean;
  config_name: string | null;
  error?: string | null;
}
const deleteVpnConfig = callable<[{ name: string }] | [string], DeleteConfigResult>(
  "delete_vpn_config"
);

interface SymlinkRepairItem {
  name: string;
  interface: string;
  ok: boolean;
  action: "none" | "created" | "replaced" | "error";
  error: string | null;
}
interface SymlinkRepairResult {
  total: number;
  repaired: number;
  results: SymlinkRepairItem[];
}
const repairSymlinks = callable<[], SymlinkRepairResult>("repair_symlinks");

interface DiagnosticsProbe {
  name: string;
  kind: "ping" | "http";
  target: string;
  ok: boolean;
  detail: string;
  latency_ms: number | null;
}
const diagnoseConnectivity = callable<[], DiagnosticsProbe[]>("diagnose_connectivity");

// Валидация имени конфига: как в awg-quick и config_manager (интерфейс = vd-<name>, макс. 15 символов)
const CONFIG_NAME_MAX_LEN = 12; // 3 (префикс "vd-") + 12 = 15
const CONFIG_NAME_REGEX = /^[a-zA-Z0-9_=+.-]+$/;

function formatTimestamp(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

function formatRate(bitsPerSecond: number): string {
  if (bitsPerSecond >= 1e6) {
    return `${(bitsPerSecond / 1e6).toFixed(bitsPerSecond >= 1e8 ? 0 : 1)} Мбит/с`;
  }
  return `${Math.round(bitsPerSecond / 1e3)} Кбит/с`;
}

function formatAge(seconds: number): string {
  return seconds < 120 ? `${seconds} с назад` : `${Math.floor(seconds / 60)} мин назад`;
}

function TunnelStatusLines({ status, rate }: { status: TunnelStatus; rate?: TunnelRate }) {
  const lines = [
    status.exit_ip
      ? `Выход: ${status.exit_ip}${status.exit_country ? ` · ${status.exit_country}` : ""}`
      : "Выход: проверяю…",
  ];
  if (status.address) {
    lines.push(
      `Адрес в VPN: ${status.address}` +
        (status.handshake_age !== null ? ` · рукопожатие ${formatAge(status.handshake_age)}` : ""),
    );
  }
  if (rate) {
    lines.push(`↓ ${formatRate(rate.rx)} · ↑ ${formatRate(rate.tx)}`);
  }
  return (
    <div style={{ fontSize: "12px", lineHeight: "18px", color: "#8b929a", margin: "2px 0 6px" }}>
      {lines.map((line) => (
        <div key={line}>{line}</div>
      ))}
    </div>
  );
}

function validateConfigName(name: string): { valid: boolean; error?: string } {
  const trimmed = name.trim();
  if (!trimmed) {
    return { valid: false, error: "Введите имя конфига" };
  }
  if (trimmed.length > CONFIG_NAME_MAX_LEN) {
    return {
      valid: false,
      error: `Макс. ${CONFIG_NAME_MAX_LEN} символов (как в имени интерфейса)`,
    };
  }
  if (!CONFIG_NAME_REGEX.test(trimmed)) {
    return {
      valid: false,
      error: "Только буквы, цифры и символы _ = + . -",
    };
  }
  return { valid: true };
}

function ImportConfigModal({
  closeModal,
  onSuccess,
}: {
  closeModal?: () => void;
  onSuccess: () => void;
}) {
  const [name, setName] = useState("");
  const [filePath, setFilePath] = useState("");
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("");

  const handlePickFile = async () => {
    try {
      const res = await openFilePicker(
        FileSelectionType.FILE,
        "/home/deck/Downloads",
        true,
        true,
        undefined,
        ["conf", "txt", "vpn", "json"],
      );
      const filename =
        res.realpath
          .split("/")
          .pop()
          ?.replace(/\.(conf|txt|vpn|json)$/, "") ?? "";
      setFilePath(res.realpath);
      setName(filename);
      setStatus(res.realpath.split("/").pop() ?? "");
    } catch (e) {
      console.error(e);
    }
  };

  const handleImport = async () => {

    try {
      const validation = validateConfigName(name);
      if (!validation.valid) {
        toaster.toast({ title: "Ошибка", body: validation.error ?? "Неверное имя конфига" });
        return;
      }
      const trimmedName = name.trim();

      setLoading(true);
      setStatus("Импорт конфига...");

      const result = await call<
        [string, string],
        { success: boolean; error: string }
      >("import_vpn_config", trimmedName, filePath);
      if (result.success) {
        setStatus("Конфиг сохранён");
        toaster.toast({ title: "Конфиг импортирован", body: trimmedName });
        onSuccess();
        closeModal?.();
      } else {
        setStatus("");
        toaster.toast({
          title: "Ошибка импорта",
          body: result.error ?? "Неизвестная ошибка",
        });
      }
    } catch (e) {
      setStatus("");
      toaster.toast({ title: "Ошибка", body: String(e) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ModalRoot onCancel={closeModal} closeModal={closeModal}>
      <DialogHeader>Импорт конфига</DialogHeader>
      <DialogBody>
        <DialogButton onClick={handlePickFile} disabled={loading}>
          {filePath ? "Выбрать другой файл" : "Выбрать файл"}
        </DialogButton>
        {!filePath && (
          <div style={{ marginTop: "8px", fontSize: "12px", color: "#8b929a" }}>
            Подходит конфиг AmneziaWG или WireGuard (.conf), ссылка vpn:// из AmneziaVPN, ссылка vless:// или конфиг sing-box (.json). Ссылку положи в файл .txt
          </div>
        )}
        {filePath && (
          <div style={{ marginTop: "12px" }}>
            <TextField
              label="Имя конфига"
              value={name}
              onChange={(e) => setName(e.target.value)}
              description="до 12 символов: a-z, 0-9, _ = + . -"
            />
          </div>
        )}
        {status && (
          <div style={{ marginTop: "8px", fontSize: "12px", color: "#8b929a" }}>
            {status}
          </div>
        )}
      </DialogBody>
      <DialogFooter>
        <DialogButton
          onClick={handleImport}
          disabled={
            loading
          }
        >
          {loading ? "Импорт..." : "Импортировать"}
        </DialogButton>
        <DialogButton onClick={closeModal}>Отмена</DialogButton>
      </DialogFooter>
    </ModalRoot>
  );
}

function DeleteConfigModal({
  configName,
  closeModal,
  onSuccess,
}: {
  configName: string;
  closeModal?: () => void;
  onSuccess: () => void;
}) {
  const [loading, setLoading] = useState(false);

  const handleDelete = async () => {
    try {
      setLoading(true);
      const result = await deleteVpnConfig({ name: configName });
      if (result.success) {
        toaster.toast({ title: "Конфиг удалён", body: configName });
        onSuccess();
        closeModal?.();
      } else {
        toaster.toast({
          title: "Ошибка удаления",
          body: result.error ?? "Неизвестная ошибка",
        });
      }
    } catch (e) {
      toaster.toast({ title: "Ошибка", body: String(e) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ModalRoot onCancel={closeModal} closeModal={closeModal}>
      <DialogHeader>Удалить конфиг</DialogHeader>
      <DialogBody>
        <div style={{ fontSize: "14px" }}>
          Удалить конфиг «{configName}»? Интерфейс будет остановлен.
        </div>
      </DialogBody>
      <DialogFooter>
        <DialogButton onClick={handleDelete} disabled={loading}>
          {loading ? "Удаление…" : "Удалить"}
        </DialogButton>
        <DialogButton onClick={closeModal}>Отмена</DialogButton>
      </DialogFooter>
    </ModalRoot>
  );
}

function Content() {
  const [configs, setConfigs] = useState<ConfigInfo[]>([]);
  const [loadingMap, setLoadingMap] = useState<Record<string, boolean>>({});
  const [errors, setErrors] = useState<VPNError[]>([]);
  const [showErrors, setShowErrors] = useState<boolean>(false);
  const [probes, setProbes] = useState<DiagnosticsProbe[] | null>(null);
  const [probesLoading, setProbesLoading] = useState<boolean>(false);
  const [repairLoading, setRepairLoading] = useState<boolean>(false);
  const [statuses, setStatuses] = useState<Record<string, TunnelStatus>>({});
  const [rates, setRates] = useState<Record<string, TunnelRate>>({});
  const [settings, setSettings] = useState<PluginSettings | null>(null);
  const lastSamples = useRef<Record<string, TunnelStatus>>({});

  const refreshStatus = useCallback(async () => {
    try {
      const result = await connectionStatus();
      const byInterface: Record<string, TunnelStatus> = {};
      const nextRates: Record<string, TunnelRate> = {};
      for (const st of result) {
        byInterface[st.interface] = st;
        const prev = lastSamples.current[st.interface];
        const dt = prev ? st.sampled_at - prev.sampled_at : 0;
        if (prev && dt > 0 && st.rx_bytes !== null && st.tx_bytes !== null
            && prev.rx_bytes !== null && prev.tx_bytes !== null
            && st.rx_bytes >= prev.rx_bytes && st.tx_bytes >= prev.tx_bytes) {
          nextRates[st.interface] = {
            rx: ((st.rx_bytes - prev.rx_bytes) * 8) / dt,
            tx: ((st.tx_bytes - prev.tx_bytes) * 8) / dt,
          };
        }
      }
      lastSamples.current = byInterface;
      setStatuses(byInterface);
      setRates(nextRates);
    } catch (error) {
      console.error("Failed to refresh connection status:", error);
    }
  }, []);

  const refreshConfigs = useCallback(async () => {
    try {
      const result = await listConfigsWithStatus();
      setConfigs(result);
    } catch (error) {
      console.error("Failed to refresh configs:", error);
    }
  }, []);

  const loadErrors = useCallback(async () => {
    try {
      const errorList = await getErrors();
      setErrors(errorList);
    } catch (error) {
      console.error("Failed to load errors:", error);
    }
  }, []);

  const handleToggle = useCallback(
    async (configName: string, enabled: boolean) => {
      setLoadingMap((prev) => ({ ...prev, [configName]: true }));
      try {
        const result = enabled
          ? await vpnStartConfig({ config_name: configName })
          : await vpnStopConfig({ config_name: configName });

        const switched = result.switched_from ?? [];
        if (!result.success) {
          toaster.toast({
            title: "Ошибка",
            body: result.error ?? "Неизвестная ошибка",
          });
          await loadErrors();
        } else if (enabled && switched.length > 0) {
          toaster.toast({
            title: "VPN переключён",
            body: `${switched.join(", ")} → ${configName}`,
          });
        } else {
          toaster.toast({
            title: enabled ? "VPN включён" : "VPN выключен",
            body: configName,
          });
        }
      } catch (error) {
        toaster.toast({
          title: "Ошибка",
          body: String(error),
        });
        await loadErrors();
      } finally {
        setLoadingMap((prev) => ({ ...prev, [configName]: false }));
        await refreshConfigs();
        await refreshStatus();
      }
    },
    [refreshConfigs, refreshStatus, loadErrors],
  );

  const handleRestoreOnBoot = useCallback(async (enabled: boolean) => {
    try {
      setSettings(await setRestoreOnBoot({ enabled }));
    } catch (e) {
      toaster.toast({ title: "Ошибка", body: String(e) });
    }
  }, []);

  const handleDiagnose = useCallback(async () => {
    setProbesLoading(true);
    try {
      const res = await diagnoseConnectivity();
      setProbes(res);
      const ok = res.filter((p) => p.ok).length;
      toaster.toast({
        title: "Проверка связи",
        body: `${ok}/${res.length} доступно`,
      });
    } catch (e) {
      toaster.toast({ title: "Ошибка диагностики", body: String(e) });
    } finally {
      setProbesLoading(false);
    }
  }, []);

  const handleRepairSymlinks = useCallback(async () => {
    setRepairLoading(true);
    try {
      const res = await repairSymlinks();
      toaster.toast({
        title: "Симлинки",
        body: `Восстановлено ${res.repaired} из ${res.total}`,
      });
      await refreshConfigs();
    } catch (e) {
      toaster.toast({ title: "Ошибка восстановления", body: String(e) });
    } finally {
      setRepairLoading(false);
    }
  }, [refreshConfigs]);

  const handleClearErrors = useCallback(async () => {
    try {
      await clearErrors();
      setErrors([]);
      toaster.toast({ title: "История ошибок очищена", body: "" });
    } catch (error) {
      toaster.toast({ title: "Ошибка очистки", body: String(error) });
    }
  }, []);

  useEffect(() => {
    refreshConfigs();
    refreshStatus();
    loadErrors();
    getSettings().then(setSettings).catch((e) => console.error("Failed to load settings:", e));

    const configsInterval = setInterval(refreshConfigs, 3000);
    const statusInterval = setInterval(refreshStatus, 3000);
    const errorsInterval = setInterval(loadErrors, 10000);

    return () => {
      clearInterval(configsInterval);
      clearInterval(statusInterval);
      clearInterval(errorsInterval);
    };
  }, [refreshConfigs, refreshStatus, loadErrors]);

  return (
    <>
      <PanelSection title="VPN Конфиги">
        {configs.length === 0 && (
          <PanelSectionRow>
            <div style={{ color: "#888", fontSize: "14px" }}>
              Нет импортированных конфигов
            </div>
          </PanelSectionRow>
        )}
        {configs.map((cfg) => (
          <PanelSectionRow key={cfg.interface}>
            <ToggleField
              label={cfg.name}
              description={`${cfg.protocol} · ${cfg.interface}`}
              checked={cfg.active}
              disabled={!!loadingMap[cfg.name]}
              onChange={(val) => handleToggle(cfg.name, val)}
            />
            {cfg.active && statuses[cfg.interface] && (
              <TunnelStatusLines
                status={statuses[cfg.interface]}
                rate={rates[cfg.interface]}
              />
            )}
            <div style={{ marginTop: "4px" }}>
              <ButtonItem
                layout="below"
                onClick={() =>
                  showModal(
                    <DeleteConfigModal
                      configName={cfg.name}
                      onSuccess={refreshConfigs}
                    />
                  )
                }
              >
                Удалить конфиг
              </ButtonItem>
            </div>
          </PanelSectionRow>
        ))}
        <PanelSectionRow>
          <ButtonItem
            layout="below"
            onClick={() =>
              showModal(<ImportConfigModal onSuccess={refreshConfigs} />)
            }
          >
            Импортировать конфиг
          </ButtonItem>
        </PanelSectionRow>
      </PanelSection>

      <PanelSection title="Настройки">
        <PanelSectionRow>
          <ToggleField
            label="Включать VPN после перезагрузки"
            description="Если VPN был включён при выключении Deck, плагин поднимет его снова"
            checked={settings?.restore_on_boot ?? true}
            disabled={settings === null}
            onChange={handleRestoreOnBoot}
          />
        </PanelSectionRow>
      </PanelSection>

      <PanelSection title="Диагностика">
        <PanelSectionRow>
          <ButtonItem
            layout="below"
            disabled={probesLoading}
            onClick={handleDiagnose}
          >
            {probesLoading ? "Проверка…" : "Проверить связь"}
          </ButtonItem>
        </PanelSectionRow>
        {probes && probes.map((p, i) => (
          <PanelSectionRow key={`${p.name}-${i}`}>
            <div
              style={{
                padding: "8px",
                fontSize: "12px",
                borderLeft: `3px solid ${p.ok ? "#4ade80" : "#f87171"}`,
                paddingLeft: "10px",
                marginBottom: "4px",
              }}
            >
              <div style={{ fontWeight: "bold" }}>
                {p.ok ? "✓" : "✗"} {p.name}
              </div>
              <div style={{ color: "#8b929a" }}>{p.detail}</div>
            </div>
          </PanelSectionRow>
        ))}
        <PanelSectionRow>
          <ButtonItem
            layout="below"
            disabled={repairLoading}
            onClick={handleRepairSymlinks}
          >
            {repairLoading ? "Восстановление…" : "Восстановить симлинки"}
          </ButtonItem>
        </PanelSectionRow>
      </PanelSection>

      <PanelSection title="Ошибки">
        <PanelSectionRow>
          <ButtonItem
            layout="below"
            onClick={() => {
              setShowErrors(!showErrors);
              if (!showErrors) loadErrors();
            }}
          >
            {showErrors
              ? "Скрыть ошибки"
              : `Просмотр ошибок${errors.length > 0 ? ` (${errors.length})` : ""}`}
          </ButtonItem>
        </PanelSectionRow>

        {showErrors && (
          <>
            {errors.length > 0 && (
              <PanelSectionRow>
                <ButtonItem layout="below" onClick={handleClearErrors}>
                  Очистить историю ошибок
                </ButtonItem>
              </PanelSectionRow>
            )}

            {errors.length === 0 ? (
              <PanelSectionRow>
                <div
                  style={{
                    padding: "10px",
                    textAlign: "center",
                    color: "#888",
                    fontSize: "14px",
                  }}
                >
                  Ошибок не обнаружено
                </div>
              </PanelSectionRow>
            ) : (
              errors
                .slice()
                .reverse()
                .map((error) => (
                  <PanelSectionRow key={`${error.timestamp}-${error.operation}`}>
                    <div
                      style={{
                        padding: "12px",
                        backgroundColor: "rgba(255, 0, 0, 0.1)",
                        borderRadius: "4px",
                        marginBottom: "8px",
                        fontSize: "12px",
                      }}
                    >
                      <div style={{ marginBottom: "4px", fontWeight: "bold" }}>
                        {formatTimestamp(error.timestamp)} - {error.operation}
                      </div>
                      <div style={{ marginBottom: "4px", color: "#FF6B6B" }}>
                        <strong>Тип:</strong> {error.error_type}
                      </div>
                      <div style={{ marginBottom: "4px" }}>
                        <strong>Сообщение:</strong> {error.message}
                      </div>
                      {Object.keys(error.details).length > 0 && (
                        <details style={{ marginTop: "8px" }}>
                          <summary style={{ cursor: "pointer", color: "#888" }}>
                            Детали
                          </summary>
                          <pre
                            style={{
                              marginTop: "4px",
                              padding: "8px",
                              backgroundColor: "rgba(0, 0, 0, 0.3)",
                              borderRadius: "4px",
                              fontSize: "11px",
                              overflow: "auto",
                            }}
                          >
                            {JSON.stringify(error.details, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  </PanelSectionRow>
                ))
            )}
          </>
        )}
      </PanelSection>
    </>
  );
}

export default definePlugin(() => {
  console.log("VPN Deck plugin initializing");

  return {
    name: "VPN Deck",
    titleView: <div className={staticClasses.Title}>VPN Deck</div>,
    content: <Content />,
    icon: <FaNetworkWired />,
    onDismount() {
      console.log("VPN Deck plugin unloading");
    },
  };
});
