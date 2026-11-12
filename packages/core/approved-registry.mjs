const approved = {
  id: 'local-create-record',
  version: '1.0.0',
  mutationName: 'create-record',
  approvalActor: 'local-test-harness',
  effects: [
    { id: 'title-saved', field: 'title' },
    { id: 'executor-saved', field: 'executorId' },
    { id: 'comment-saved', field: 'comment' }
  ]
};

export function assertApprovedOperation(operation, scenario) {
  if (operation.id !== approved.id || operation.version !== approved.version || operation.mutation?.name !== approved.mutationName) {
    throw Object.assign(new Error('Операция не входит в доверенный реестр локального ядра'), { code: 'CONTRACT_INVALID' });
  }
  if (scenario.status !== 'APPROVED' || scenario.approval?.actor !== approved.approvalActor) {
    throw Object.assign(new Error('Утверждение сценария не совпадает с доверенным реестром'), { code: 'CONTRACT_INVALID' });
  }
  if (operation.effects.length !== approved.effects.length || approved.effects.some(effect => !operation.effects.some(candidate => candidate.id === effect.id && candidate.field === effect.field))) {
    throw Object.assign(new Error('Набор обязательных эффектов не совпадает с доверенным реестром'), { code: 'CONTRACT_INVALID' });
  }
}
