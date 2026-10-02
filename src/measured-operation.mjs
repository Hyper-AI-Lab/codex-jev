import { configuration } from './hardened-policy.mjs';
import { entrypointError } from './entrypoint-error.mjs';
import { InvocationLedger } from './invocation-ledger.mjs';

const numeric = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1e15;

export function operationMetrics(name, value, response, elapsed) {
  const metrics = { responseBytes: Buffer.byteLength(JSON.stringify(response)), durationMs: Math.max(0, elapsed) };
  for (const key of ['jevRequests', 'retrievalMs', 'selectionMs']) {
    if (numeric(value.metrics?.[key])) metrics[key] = value.metrics[key];
  }
  if (value.metrics?.jevRequests > 0) {
    if (numeric(value.metrics?.jevUsage?.input_tokens)) metrics.jevInputTokens = value.metrics.jevUsage.input_tokens;
    if (numeric(value.metrics?.jevUsage?.output_tokens)) metrics.jevOutputTokens = value.metrics.jevUsage.output_tokens;
  }
  if (numeric(value.metrics?.selectedEvidenceBytes)) metrics.evidenceBytes = value.metrics.selectedEvidenceBytes;
  if (value.mode === 'cache') metrics.cacheHits = 1;
  if (value.mode === 'bypass' || value.mode === 'local') metrics.localBypasses = 1;
  if (name === 'read_selected_evidence' && typeof value.content === 'string') {
    metrics.followupBytes = Buffer.byteLength(value.content); metrics.followupReads = 1;
  }
  return metrics;
}

export async function measuredOperation(service, name, input, operation) {
  const started = performance.now();
  let ledger, id, unavailable = false;
  try {
    if ((await configuration(service.home)).measurement_enabled) {
      ledger = new InvocationLedger(service.home);
      id = ledger.begin({ workspace: service.boundRoot, operation: name, input,
        revision: service.buildHash, origin: service.measurementOrigin });
    }
  } catch { unavailable = true; }
  let value, isError = false;
  try { value = await operation(input); }
  catch (error) { value = await entrypointError(error, service.home); isError = true; }
  if (id) value = { ...value, measurementId: id };
  if (unavailable) value = { ...value, measurementWarning: 'Invocation measurement is unavailable; task attribution is not verified.' };
  const envelope = () => ({ ...(isError ? { isError: true } : {}),
    content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value });
  try {
    if (id) ledger.finish(id, { status: isError ? 'error' : 'success',
      metrics: operationMetrics(name, value, envelope(), performance.now() - started) });
  } catch {
    delete value.measurementId;
    value.measurementWarning = 'Invocation recording did not complete; task attribution is not verified.';
  } finally { ledger?.close(); }
  return envelope();
}
