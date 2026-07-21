/**
 * Operations configuration copy (t105) — the ZK shared object root, the database pane and the Redis
 * pane.
 *
 * Same contract as `operationsFallback.ts`, and here for the same reason: this is additive
 * operator-surface copy, authored in pt-PT, shipping an explicit English fallback for the other 13
 * catalogs until each machine-quality locale receives native review. Keeping it in one typed pair
 * stops 13 catalogs from silently missing a safety label.
 *
 * **The copy in here carries safety weight, so two rules govern it.**
 *
 * 1. **Never claim an assurance the code does not make.** `settings.zkRoot.cannotVerify.body` is
 *    the load-bearing string on this surface: the server can check that the declared path is
 *    absolute, is the expected root, exists and is writable, and it *cannot* check that the path is
 *    a genuinely shared mount rather than node-local storage. The copy says that outright. A
 *    translation that softens it into "o servidor valida o caminho" would turn an honest disclosure
 *    into a false assurance, which is worse than leaving the string in English.
 * 2. **Never describe a read-only pane as configuration.** The database and Redis panes exist
 *    because the operator asked to configure those subsystems, and the honest answer is that every
 *    value is resolved once at process start. The `readOnly.body` strings say where each value
 *    comes from and what has to be restarted, and must not be reworded into "definições".
 */
export const opsConfigPtPT = {
  // Shared note appended to any environment row whose value is or embeds a credential.
  'settings.env.secretNote': '(contém uma credencial — nunca é apresentada aqui)',

  // — Raiz de objetos de conhecimento nulo ————————————————————————————————
  'settings.zkRoot.cardTitle': 'Raiz de objetos partilhada (conhecimento nulo)',
  'settings.zkRoot.intro':
    'Os repositórios de conhecimento nulo guardam objetos opacos em <data_dir>/zk-repositories. Em PostgreSQL/HA ficam desativados até um operador declarar explicitamente que essa diretoria é um ponto de montagem partilhado por todos os nós.',
  'settings.zkRoot.cannotVerify.title': 'O que esta declaração assegura — e o que não assegura',
  'settings.zkRoot.cannotVerify.body':
    'O servidor verifica que o caminho é absoluto, que corresponde exatamente à raiz esperada, que existe e que é gravável. Não consegue verificar que é realmente uma montagem partilhada e não armazenamento local do nó: a partir de um único nó não há nada que os distinga. Essa parte é uma declaração sua. Se estiver errada, cada nó guarda objetos que os restantes não veem, sem qualquer erro.',
  'settings.zkRoot.fromEnv.title': 'Definido pelo ambiente',
  'settings.zkRoot.fromEnv.body':
    'CHANCELA_ZK_SHARED_OBJECT_ROOT está definido no ambiente do processo e tem precedência sobre este campo. Altere-o onde o serviço é lançado; editar aqui não teria efeito.',
  'settings.zkRoot.field.label': 'Raiz de objetos partilhada',
  'settings.zkRoot.field.hint':
    'Caminho absoluto. Tem de corresponder exatamente a <data_dir>/zk-repositories. Deixar vazio remove a declaração e fecha o bloqueio no próximo arranque.',
  'settings.zkRoot.field.help':
    'Não é uma escolha de local de armazenamento: é a confirmação de que esta diretoria é a montagem partilhada. Qualquer outro caminho é recusado.',
  'settings.zkRoot.save': 'Guardar declaração',
  'settings.zkRoot.saved': 'Declaração guardada. Aplica-se no próximo arranque do servidor.',
  'settings.zkRoot.restart.title': 'Guardado, ainda não aplicado',
  'settings.zkRoot.restart.body':
    'A raiz de objetos é resolvida uma única vez, no arranque do processo. O valor está guardado, mas o servidor em execução continua a usar o que leu quando arrancou — reinicie-o para aplicar.',
  'settings.zkRoot.live.title': 'Estado em execução',
  'settings.zkRoot.live.hint':
    'O que este processo resolveu no arranque, não o que está guardado. É esta a autoridade sobre o que está efetivamente ativo.',
  'settings.zkRoot.live.col.fact': 'Facto',
  'settings.zkRoot.live.col.value': 'Valor',
  'settings.zkRoot.live.state': 'Armazenamento de repositórios',
  'settings.zkRoot.live.state.open': 'Ativo',
  'settings.zkRoot.live.state.closed': 'Desativado (fecho seguro)',
  'settings.zkRoot.live.required': 'Declaração exigida neste servidor',
  'settings.zkRoot.live.required.yes': 'Sim — backend PostgreSQL/HA',
  'settings.zkRoot.live.required.no': 'Não — instância de nó único',
  'settings.zkRoot.live.root': 'Raiz em uso',
  'settings.zkRoot.live.source': 'Origem do valor',
  'settings.zkRoot.live.source.environment': 'Ambiente (CHANCELA_ZK_SHARED_OBJECT_ROOT)',
  'settings.zkRoot.live.source.settings': 'Definições desta instância',
  'settings.zkRoot.live.source.unset': 'Não declarada',
  'settings.zkRoot.live.reason.title': 'Motivo do fecho',

  // — Base de dados ————————————————————————————————————————————————————
  'settings.database.cardTitle': 'Base de dados',
  'settings.database.intro':
    'O backend durável desta instância: o motor selecionado, onde os dados residem e como a chave de cifra é obtida.',
  'settings.database.readOnly.title': 'Apenas leitura — resolvido no arranque',
  'settings.database.readOnly.body':
    'Todos estes valores são lidos uma única vez quando o processo arranca e nenhum ponto final os pode escrever. São apresentados como factos, e não como um formulário que aparentaria funcionar sem produzir efeito até um reinício. Altere-os onde o serviço é lançado e reinicie. O que é ajustável em execução — o nível de registo da base de dados — está em Operações › Registos.',
  'settings.database.env.hint':
    'Variáveis de ambiente lidas em AppState::try_from_env. A coluna da direita indica o valor assumido quando a variável não está definida.',
  'settings.database.env.backend': 'Motor durável selecionado: sqlite (predefinição) ou postgres.',
  'settings.database.env.url': 'Cadeia de ligação libpq do PostgreSQL, exigida com o backend postgres.',
  'settings.database.env.urlFile':
    'Ficheiro que contém a cadeia de ligação, para entrega por segredo de contentor. Tem precedência sobre DATABASE_URL.',
  'settings.database.env.dataDir': 'Diretoria de dados que suporta a persistência em ficheiro.',
  'settings.database.env.key': 'Palavra-passe SQLCipher da base de dados SQLite cifrada.',
  'settings.database.env.keyFile': 'Ficheiro que contém a palavra-passe SQLCipher.',
  'settings.database.env.keySource':
    'Classe de origem da chave. operator preserva o comportamento de CHANCELA_DB_KEY / CHANCELA_DB_KEY_FILE.',
  'settings.database.env.sslMode':
    'Modo TLS da ligação ao PostgreSQL. verify-full é a postura defensável em produção.',
  'settings.database.related.title': 'Relacionado',
  'settings.database.related.logging':
    'O nível de registo da base de dados é ajustável em execução e vive nos níveis de log da plataforma — o seu único escritor.',
  'settings.database.related.dataStatus':
    'Estado de persistência, postura de cifra e utilização em disco são apresentados em Gestão de dados.',

  // — Redis ——————————————————————————————————————————————————————————
  'settings.cache.cardTitle': 'Redis e estado partilhado',
  'settings.cache.intro':
    'Cache opcional e, em PostgreSQL/HA, o estado partilhado do cluster: sessões, limitador de tráfego global e barramento de invalidação entre nós.',
  'settings.cache.readOnly.body':
    'Apenas leitura, resolvido no arranque, pela mesma razão que a base de dados. Note a assimetria: a cache é tolerante a falhas — um Redis inacessível degrada para ausência de cache —, ao passo que o estado partilhado em PostgreSQL/HA é exigido e o arranque falha sem ele.',
  'settings.cache.env.title': 'Cache e estado partilhado',
  'settings.cache.env.hint':
    'Só têm efeito quando o servidor é compilado com a funcionalidade redis. Sem elas, a cache é inerte e o estado partilhado mantém-se local ao nó.',
  'settings.cache.env.url': 'URL do Redis, por exemplo redis://redis:6379.',
  'settings.cache.env.urlFile':
    'Ficheiro que contém o URL do Redis, para entrega por segredo de contentor. Tem precedência sobre REDIS_URL.',
  'settings.cache.env.cache':
    'Defina moka para ativar uma cache em processo quando não existe Redis. Sem rede e sem funcionalidade adicional.',
  'settings.cache.cluster.title': 'Cluster e nós',
  'settings.cache.cluster.hint':
    'Intervalos em segundos inteiros, cada um limitado a um mínimo de 1 s para que um valor mal configurado nunca provoque um ciclo de espera ativa.',
  'settings.cache.env.nodeRole': 'Papel do nó no cluster.',
  'settings.cache.env.promotePoll': 'Período de sondagem de promoção do seguidor, em segundos.',
  'settings.cache.env.heartbeat': 'Período de pulsação do líder, em segundos.',
  'settings.cache.env.changefeedPoll': 'Período de sondagem do fluxo de alterações, em segundos.',
  'settings.cache.env.watchdog': 'Período do vigilante do líder, em segundos.',
  'settings.cache.env.staleAfter': 'Tempo após o qual um nó é considerado desatualizado.',
  'settings.cache.env.writeMode': 'Modo de escrita do cluster.',
  'settings.cache.related.logging':
    'Os níveis de registo são ajustáveis em execução e vivem nos níveis de log da plataforma.',
} as const;

export const opsConfigEnglish = {
  'settings.env.secretNote': '(contains a credential — never displayed here)',

  'settings.zkRoot.cardTitle': 'Shared object root (zero-knowledge)',
  'settings.zkRoot.intro':
    'Zero-knowledge repositories store opaque objects under <data_dir>/zk-repositories. On PostgreSQL/HA they stay disabled until an operator explicitly declares that this directory is a mount shared by every node.',
  'settings.zkRoot.cannotVerify.title': 'What this declaration does — and does not — assure',
  'settings.zkRoot.cannotVerify.body':
    'The server checks that the path is absolute, that it matches the expected root exactly, that it exists, and that it is writable. It cannot check that it is genuinely a shared mount rather than node-local storage: from a single node nothing distinguishes the two. That part is your declaration. If it is wrong, each node holds objects the others cannot see, with no error anywhere.',
  'settings.zkRoot.fromEnv.title': 'Set by the environment',
  'settings.zkRoot.fromEnv.body':
    'CHANCELA_ZK_SHARED_OBJECT_ROOT is set in the process environment and takes precedence over this field. Change it where the service is launched; editing here would have no effect.',
  'settings.zkRoot.field.label': 'Shared object root',
  'settings.zkRoot.field.hint':
    'Absolute path. It must match <data_dir>/zk-repositories exactly. Leaving it empty clears the declaration and closes the interlock at the next start.',
  'settings.zkRoot.field.help':
    'Not a choice of storage location: it is the confirmation that this directory is the shared mount. Any other path is refused.',
  'settings.zkRoot.save': 'Save declaration',
  'settings.zkRoot.saved': 'Declaration saved. It applies at the next server start.',
  'settings.zkRoot.restart.title': 'Saved, not yet applied',
  'settings.zkRoot.restart.body':
    'The object root is resolved once, when the process starts. The value is stored, but the running server is still using what it read at startup — restart it to apply.',
  'settings.zkRoot.live.title': 'Running state',
  'settings.zkRoot.live.hint':
    'What this process resolved at startup, not what is saved. This is the authority on what is actually active.',
  'settings.zkRoot.live.col.fact': 'Fact',
  'settings.zkRoot.live.col.value': 'Value',
  'settings.zkRoot.live.state': 'Repository storage',
  'settings.zkRoot.live.state.open': 'Enabled',
  'settings.zkRoot.live.state.closed': 'Disabled (fail-closed)',
  'settings.zkRoot.live.required': 'Declaration required on this server',
  'settings.zkRoot.live.required.yes': 'Yes — PostgreSQL/HA backend',
  'settings.zkRoot.live.required.no': 'No — single-node instance',
  'settings.zkRoot.live.root': 'Root in use',
  'settings.zkRoot.live.source': 'Where the value came from',
  'settings.zkRoot.live.source.environment': 'Environment (CHANCELA_ZK_SHARED_OBJECT_ROOT)',
  'settings.zkRoot.live.source.settings': "This instance's settings",
  'settings.zkRoot.live.source.unset': 'Not declared',
  'settings.zkRoot.live.reason.title': 'Why it is closed',

  'settings.database.cardTitle': 'Database',
  'settings.database.intro':
    "This instance's durable backend: the selected engine, where the data lives, and how the encryption key is obtained.",
  'settings.database.readOnly.title': 'Read-only — resolved at startup',
  'settings.database.readOnly.body':
    'Every one of these values is read once when the process starts, and no endpoint can write them. They are shown as facts rather than as a form that would appear to work while doing nothing until a restart. Change them where the service is launched, and restart. What IS adjustable at runtime — the database log level — lives with the platform log levels, linked below.',
  'settings.database.env.hint':
    'Environment variables read in AppState::try_from_env. The right-hand column is the value assumed when the variable is not set.',
  'settings.database.env.backend': 'Selected durable engine: sqlite (default) or postgres.',
  'settings.database.env.url': 'PostgreSQL libpq connection string, required with the postgres backend.',
  'settings.database.env.urlFile':
    'File containing the connection string, for container-secret delivery. Takes precedence over DATABASE_URL.',
  'settings.database.env.dataDir': 'Data directory backing on-disk persistence.',
  'settings.database.env.key': 'SQLCipher passphrase for the encrypted SQLite database.',
  'settings.database.env.keyFile': 'File containing the SQLCipher passphrase.',
  'settings.database.env.keySource':
    'Key-source class. operator preserves the CHANCELA_DB_KEY / CHANCELA_DB_KEY_FILE behaviour.',
  'settings.database.env.sslMode':
    'TLS mode for the PostgreSQL connection. verify-full is the defensible production posture.',
  'settings.database.related.title': 'Related',
  'settings.database.related.logging':
    'The database log level is runtime-adjustable and lives with the platform log levels — its single writer.',
  'settings.database.related.dataStatus':
    'Persistence state, encryption posture and on-disk usage are shown in Gestão de dados.',

  'settings.cache.cardTitle': 'Redis and shared state',
  'settings.cache.intro':
    'The optional cache and, on PostgreSQL/HA, the cluster shared state: sessions, the global rate limiter, and the cross-node invalidation bus.',
  'settings.cache.readOnly.body':
    'Read-only, resolved at startup, for the same reasons as the database. Note the asymmetry: the cache is fail-open — an unreachable Redis degrades to no cache — whereas shared state on PostgreSQL/HA is required and startup fails without it.',
  'settings.cache.env.title': 'Cache and shared state',
  'settings.cache.env.hint':
    'These take effect only when the server is built with the redis feature. Without them the cache is inert and shared state stays node-local.',
  'settings.cache.env.url': 'Redis URL, for example redis://redis:6379.',
  'settings.cache.env.urlFile':
    'File containing the Redis URL, for container-secret delivery. Takes precedence over REDIS_URL.',
  'settings.cache.env.cache':
    'Set to moka to enable an in-process cache when there is no Redis. No network, no extra feature.',
  'settings.cache.cluster.title': 'Cluster and nodes',
  'settings.cache.cluster.hint':
    'Whole-second intervals, each clamped to a 1s minimum so a misconfigured value can never busy-spin a poll loop.',
  'settings.cache.env.nodeRole': "The node's role in the cluster.",
  'settings.cache.env.promotePoll': 'Follower promotion poll period, in seconds.',
  'settings.cache.env.heartbeat': 'Leader heartbeat period, in seconds.',
  'settings.cache.env.changefeedPoll': 'Change-feed poll period, in seconds.',
  'settings.cache.env.watchdog': 'Leader watchdog period, in seconds.',
  'settings.cache.env.staleAfter': 'How long before a node is considered stale.',
  'settings.cache.env.writeMode': 'Cluster write mode.',
  'settings.cache.related.logging':
    'Log levels are runtime-adjustable and live with the platform log levels.',
} as const satisfies Record<keyof typeof opsConfigPtPT, string>;
