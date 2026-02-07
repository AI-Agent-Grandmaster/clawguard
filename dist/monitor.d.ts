/**
 * ClawGuard Continuous Monitoring
 *
 * Runtime watching for installed skills:
 * - Periodic re-scans
 * - File change detection
 * - Behavior baseline comparison
 * - Alert on anomalies
 */
import { EventEmitter } from 'events';
export interface MonitorConfig {
    enabled: boolean;
    watchPaths: string[];
    scanIntervalMs: number;
    alertWebhook?: string;
    alertEmail?: string;
}
export interface Alert {
    id: string;
    timestamp: string;
    skillPath: string;
    skillName: string;
    type: 'file_change' | 'new_finding' | 'capability_change' | 'hash_mismatch';
    severity: 'info' | 'warning' | 'critical';
    message: string;
    details?: unknown;
}
declare class SkillMonitor extends EventEmitter {
    private config;
    private states;
    private watchers;
    private scanInterval?;
    private running;
    loadConfig(): Promise<void>;
    saveConfig(): Promise<void>;
    start(): Promise<void>;
    stop(): Promise<void>;
    private setupWatcher;
    private scanPath;
    private alert;
    private logAlert;
    private sendWebhook;
    addPath(path: string): Promise<void>;
    removePath(path: string): Promise<void>;
    enable(): Promise<void>;
    disable(): Promise<void>;
    getConfig(): MonitorConfig;
    getAlerts(limit?: number): Promise<Alert[]>;
}
export declare function getMonitor(): SkillMonitor;
export declare function startMonitor(): Promise<void>;
export declare function stopMonitor(): Promise<void>;
export {};
