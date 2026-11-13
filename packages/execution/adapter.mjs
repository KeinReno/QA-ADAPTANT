export class ExecutionAdapterError extends Error {
  constructor(code, message, { dispatched = false, runId = null } = {}) {
    super(message); this.name = 'ExecutionAdapterError'; this.code = code; this.dispatched = dispatched; this.runId = runId;
  }
}

export function assertExecutionAdapter(adapter) {
  for (const method of ['capabilities', 'prepare', 'start', 'observe', 'cancel', 'reconcile']) {
    if (typeof adapter?.[method] !== 'function') throw new ExecutionAdapterError('ADAPTER_INVALID', `ExecutionAdapter не реализует ${method}`);
  }
  if (typeof adapter.id !== 'string' || !adapter.id) throw new ExecutionAdapterError('ADAPTER_INVALID', 'ExecutionAdapter должен иметь id');
  return adapter;
}
