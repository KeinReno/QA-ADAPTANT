const approved = {
  id: 'local-create-record',
  version: '1.0.0',
  mutationName: 'create-record',
  approvalActor: 'local-test-harness',
  inputs: ['comment', 'executorId', 'title'],
  effects: [
    { id: 'title-saved', field: 'title' },
    { id: 'executor-saved', field: 'executorId' },
    { id: 'comment-saved', field: 'comment' }
  ]
};

function reject(message) {
  throw Object.assign(new Error(message), { code: 'CONTRACT_INVALID' });
}

export function assertApprovedOperation(operation, scenario) {
  if (operation.id !== approved.id || operation.version !== approved.version || operation.mutation?.name !== approved.mutationName) {
    reject('Операция не входит в доверенный реестр локального ядра');
  }
  if (scenario.status !== 'APPROVED' || scenario.approval?.actor !== approved.approvalActor) {
    reject('Утверждение сценария не совпадает с доверенным реестром');
  }
  const inputs = operation.inputs || {};
  const keys = Object.keys(inputs).sort();
  if (keys.length !== approved.inputs.length || approved.inputs.some((key, index) => key !== keys[index])) {
    reject('Набор входов не совпадает с доверенным реестром');
  }
  if (operation.effects.length !== approved.effects.length) reject('Набор обязательных эффектов не совпадает с доверенным реестром');
  for (const effect of approved.effects) {
    const candidate = operation.effects.find(item => item.id === effect.id && item.field === effect.field);
    if (!candidate) reject('Набор обязательных эффектов не совпадает с доверенным реестром');
    if (candidate.required !== true) reject('Утверждённый эффект обязан оставаться обязательным');
    if (candidate.appliesWhen != null) reject('Утверждённый эффект не может быть отключён условием appliesWhen');
    if (!Object.hasOwn(inputs, effect.field) || candidate.equals !== inputs[effect.field]) {
      reject('Ожидаемое значение эффекта не совпадает с утверждённым входом');
    }
  }
}
