import os from 'node:os';
import fs from 'node:fs';

export function classifyToolError(error) {
  const message = error instanceof Error ? error.message : String(error);
  if (/Missing OAuth scope/i.test(message)) return 'forbidden';
  if (/explicit_confirmation_required/i.test(message)) return 'approval_required';
  if (/invalid_or_expired_approval/i.test(message)) return 'approval_invalid';
  if (/queue_full/i.test(message)) return 'queue_full';
  if (/timed_out|timeout/i.test(message)) return 'execution_timeout';
  if (/invalid_|required|expected|schema|validation/i.test(message)) return 'validation_failed';
  return 'tool_execution_failed';
}

export function systemMetrics() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const loadAvg = os.loadavg();
  const cpus = os.cpus();

  let diskInfo = null;
  try {
    if (typeof fs.statfsSync === 'function') {
      const stats = fs.statfsSync('/');
      const totalBytes = Number(stats.blocks) * Number(stats.bsize);
      const freeBytes = Number(stats.bfree) * Number(stats.bsize);
      diskInfo = {
        total_bytes: totalBytes,
        free_bytes: freeBytes,
        used_bytes: totalBytes - freeBytes,
        used_percentage: Math.round(((totalBytes - freeBytes) / totalBytes) * 100)
      };
    }
  } catch {}

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    uptime_seconds: os.uptime(),
    cpu: {
      cores: cpus.length,
      model: cpus[0]?.model || 'unknown',
      load_average_1m: loadAvg[0],
      load_average_5m: loadAvg[1],
      load_average_15m: loadAvg[2]
    },
    memory: {
      total_bytes: totalMem,
      free_bytes: freeMem,
      used_bytes: usedMem,
      used_percentage: Math.round((usedMem / totalMem) * 100)
    },
    disk: diskInfo
  };
}
